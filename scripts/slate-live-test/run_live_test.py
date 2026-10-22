#!/usr/bin/env python3
"""Restartable, nonsecret CLI runner for the SLATE Studio Dev lifecycle."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONFIG_PATH = HERE / "config.json"
RESULTS = HERE / "results"
CHECKPOINT_PATH = RESULTS / "checkpoint.json"
EVIDENCE_PATH = RESULTS / "live-evidence.json"
REPORT_PATH = RESULTS / "live-test-report.md"
READ_FAILURE_PATH = RESULTS / "read-failures.json"
EXPLORER = "https://explorer-studio-dev.genlayer.com/tx/"
HEX_ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class LiveBlocker(RuntimeError):
    pass


def clean(value: str) -> str:
    return ANSI.sub("", value).replace("\r", "")


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def cli(*args: str, check: bool = True, timeout: float | None = None) -> str:
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["FORCE_COLOR"] = "0"
    try:
        result = subprocess.run(
            ["genlayer", *args], cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        partial = error.stdout or ""
        raise LiveBlocker(
            f"genlayer {' '.join(args)} timed out after {timeout}s; "
            f"partial output: {clean(partial if isinstance(partial, str) else partial.decode(errors='replace'))[-2000:]}"
        ) from error
    output = clean(result.stdout)
    if check and result.returncode != 0:
        raise LiveBlocker(output[-2000:] or f"genlayer {' '.join(args)} failed")
    return output


def initial_checkpoint(config: dict[str, Any]) -> dict[str, Any]:
    return {
        "network": config["network"],
        "chain_id": config["chain_id"],
        "rpc": config["rpc"],
        "contract": config["contract"],
        "wallets": {},
        "values": {},
        "steps": {},
        "transactions": [],
        "assertions": [],
        "status": "NOT_STARTED",
        "last_verified_checkpoint": "initialized",
    }


def checkpoint(config: dict[str, Any]) -> dict[str, Any]:
    current = load_json(CHECKPOINT_PATH, None)
    if current is None:
        current = initial_checkpoint(config)
        save_json(CHECKPOINT_PATH, current)
    if current.get("contract") != config["contract"] or current.get("chain_id") != config["chain_id"]:
        raise LiveBlocker("checkpoint belongs to a different deployment or chain")
    return current


def parse_result(output: str) -> Any:
    text = clean(output)
    marker = text.rfind("Result:")
    if marker < 0:
        raise LiveBlocker("CLI call did not return a Result block")
    payload = text[marker + len("Result:"):]
    payload = payload.split("✔ Read operation successfully executed", 1)[0]
    lines = [line.strip() for line in payload.splitlines() if line.strip()]
    if not lines:
        return ""
    first = lines[0]
    if first == "true":
        return True
    if first == "false":
        return False
    if re.fullmatch(r"[0-9]+", first):
        return int(first)
    if first.startswith("{") or first.startswith("["):
        try:
            return json.loads(first)
        except json.JSONDecodeError:
            try:
                return ast.literal_eval(first)
            except (ValueError, SyntaxError):
                pass
    return first


def read_call(config: dict[str, Any], method: str, *args: str) -> Any:
    command = ["call", config["contract"], method]
    if args:
        command += ["--args", *args]
    command_text = ["genlayer", *command]
    attempts: list[dict[str, Any]] = []
    for attempt, delay in enumerate((0, 2, 5), 1):
        if delay:
            time.sleep(delay)
        env = dict(os.environ)
        env["NO_COLOR"] = "1"
        env["FORCE_COLOR"] = "0"
        result = subprocess.run(
            command_text, cwd=ROOT, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        stdout = clean(result.stdout)
        stderr = clean(result.stderr)
        combined = stdout + ("\n" + stderr if stderr else "")
        try:
            if result.returncode == 0:
                try:
                    return parse_result(stdout)
                except LiveBlocker:
                    return parse_result(combined)
        except LiveBlocker as error:
            attempts.append({
                "attempt": attempt, "exit_code": result.returncode,
                "stdout": stdout, "stderr": stderr, "error": str(error),
            })
            break
        attempts.append({
            "attempt": attempt, "exit_code": result.returncode,
            "stdout": stdout, "stderr": stderr,
        })
        transient = any(token in combined.lower() for token in (
            "fetch failed", "econnreset", "etimedout", "econnrefused",
            "429", "-32429", "temporarily unavailable", "timeout",
        ))
        if result.returncode == 0 or not transient:
            break
    diagnostic = {
        "command": command_text,
        "method": method,
        "args": list(args),
        "attempts": attempts,
    }
    save_json(READ_FAILURE_PATH, diagnostic)
    last = attempts[-1] if attempts else {}
    detail = last.get("stderr") or last.get("stdout") or "no CLI output"
    raise LiveBlocker(f"read failed after bounded retries: {' '.join(command_text)}\n{detail[-3000:]}")


def account_info() -> tuple[str, str]:
    output = cli("account")
    address = re.search(r"address:\s*['\"](0x[0-9a-fA-F]{40})['\"]", output)
    balance = re.search(r"balance:\s*['\"]([^'\"]+)['\"]", output)
    if not address:
        address = HEX_ADDRESS.search(output)
    if not address:
        raise LiveBlocker("could not determine active signer address")
    return address.group(1).lower(), balance.group(1) if balance else "unknown"


def use_wallet(name: str, expected: str) -> str:
    cli("account", "use", name)
    actual, balance = account_info()
    if actual != expected.lower():
        raise LiveBlocker(f"active signer mismatch for {name}: {actual} != {expected.lower()}")
    return balance


def verify_network(config: dict[str, Any]) -> None:
    output = cli("network", "info")
    if config["network"] not in output or str(config["chain_id"]) not in output or config["rpc"] not in output:
        raise LiveBlocker("CLI network profile is not the expected Studio Dev chain 61997 profile")


def framed_digest(domain: str, *parts: str) -> str:
    values = (domain,) + tuple(str(part) for part in parts)
    encoded = "".join(f"{len(value.encode('utf-8'))}:{value}" for value in values).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def policy_id(org_id: str, version: int) -> str:
    return "pol-" + framed_digest("SLATE-POLICY-ID-V1", org_id, str(version))


def resource_id(org_id: str, key: str, description: str) -> str:
    return "rsc-" + framed_digest("SLATE-RESOURCE-ID-V1", org_id, key, description)


def proposed_digest(org_id: str, base_version: int, policy: str) -> str:
    return framed_digest("SLATE-PROPOSED-POLICY-V1", org_id, str(base_version), policy)


def amendment_id(org_id: str, sequence: int, proposal_digest: str, rationale: str) -> str:
    return "amd-" + framed_digest("SLATE-AMENDMENT-ID-V1", org_id, str(sequence), proposal_digest, rationale)


def action_id(org_id: str, sequence: int, policy: dict[str, Any], resource: dict[str, Any], desired: bool, purpose: str) -> str:
    request = framed_digest(
        "SLATE-ACTION-REQUEST-V1", org_id, policy["active_agent"], policy["active_policy_id"],
        str(policy["version"]), policy["active_policy_digest"], resource["resource_id"],
        str(resource["enabled"]), str(desired), purpose,
    )
    return "act-" + framed_digest("SLATE-ACTION-ID-V1", org_id, str(sequence), request)


def estimate(config: dict[str, Any], method: str, args: list[str]) -> Any:
    output = cli("estimate-fees", config["contract"], method, "--args", *args, "--json", timeout=90)
    lines = [line.strip() for line in clean(output).splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            continue
    return {"raw_summary": clean(output)[-1000:]}


def receipt_outcome(tx_hash: str) -> tuple[str, str]:
    """Read status fields without persisting the raw validator payload."""
    output = cli(
        "receipt", tx_hash, "--wait-until", "finalized", "--retries", "100",
        "--interval", "5000", "--raw", check=False,
    )
    normalized = clean(output).lower()
    status_match = re.search(r"status_name:\s*['\"]([^'\"]+)['\"]", normalized)
    result_match = re.search(r"txexecutionresultname:\s*['\"]([^'\"]+)['\"]", normalized)
    status = status_match.group(1).upper() if status_match else "UNKNOWN"
    result = result_match.group(1).upper() if result_match else "UNKNOWN"
    if status == "FINALIZED" and result == "FINISHED_WITH_RETURN":
        return status, result
    if status == "FINALIZED" and result in {"FINISHED_WITH_ERROR", "REVERTED", "ROLLBACK"}:
        return status, "ERROR/ROLLBACK"
    return status, result


def finalize_existing(tx: dict[str, Any]) -> bool:
    status, result = receipt_outcome(tx["hash"])
    if status == "FINALIZED" and result == "FINISHED_WITH_RETURN":
        tx["consensus_status"] = status
        tx["execution_result"] = result
        return True
    if status == "FINALIZED" and result == "ERROR/ROLLBACK":
        tx["consensus_status"] = status
        tx["execution_result"] = result
        return False
    raise LiveBlocker(f"transaction {tx['hash']} has an unknown final state; no retry was submitted")


def run_write(config: dict[str, Any], state: dict[str, Any], step: str, method: str,
              wallet_name: str, signer: str, args: list[str]) -> dict[str, Any]:
    existing = state["steps"].get(step)
    if existing and existing.get("status") == "PASS":
        return existing
    if existing and existing.get("tx_hash"):
        tx = next(item for item in state["transactions"] if item["hash"] == existing["tx_hash"])
        if not finalize_existing(tx):
            raise LiveBlocker(f"previous {step} transaction finalized with execution failure")
        existing["status"] = "PASS"
        save_json(CHECKPOINT_PATH, state)
        return existing

    balance = use_wallet(wallet_name, signer)
    fee_estimate = estimate(config, method, args)
    command = ["genlayer", "write", config["contract"], method, "--wallet", "keystore"]
    if not isinstance(fee_estimate, dict) or not fee_estimate.get("feeValue") or not fee_estimate.get("distribution"):
        raise LiveBlocker(f"fee estimate for {method} did not contain a nonzero feeValue and distribution")
    fee_options = {"distribution": fee_estimate["distribution"]}
    if fee_estimate.get("messageAllocations") is not None:
        fee_options["messageAllocations"] = fee_estimate["messageAllocations"]
    command += ["--fees", json.dumps(fee_options, separators=(",", ":")), "--fee-value", str(fee_estimate["feeValue"]), "--args", *args]
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["FORCE_COLOR"] = "0"
    process = subprocess.Popen(command, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, bufsize=1)
    output: list[str] = []
    tx_hash = ""
    awaiting_hash = False
    for line in process.stdout or []:
        cleaned = clean(line)
        output.append(cleaned)
        if "Write Transaction Hash:" in cleaned and not tx_hash:
            match = TX_HASH.search(cleaned)
            if match:
                tx_hash = match.group(0)
                tx = {
                    "step": step, "method": method, "signer": signer.lower(),
                    "args": args, "hash": tx_hash, "explorer": EXPLORER + tx_hash,
                    "consensus_status": "SUBMITTED", "execution_result": "UNKNOWN",
                    "balance_before": balance, "fee_estimate": fee_estimate,
                }
                state["transactions"].append(tx)
                state["steps"][step] = {"status": "SUBMITTED", "tx_hash": tx_hash}
                save_json(CHECKPOINT_PATH, state)
            else:
                awaiting_hash = True
        elif awaiting_hash and not tx_hash:
            match = TX_HASH.search(cleaned)
            if match:
                tx_hash = match.group(0)
                tx = {
                    "step": step, "method": method, "signer": signer.lower(),
                    "args": args, "hash": tx_hash, "explorer": EXPLORER + tx_hash,
                    "consensus_status": "SUBMITTED", "execution_result": "UNKNOWN",
                    "balance_before": balance, "fee_estimate": fee_estimate,
                }
                state["transactions"].append(tx)
                state["steps"][step] = {"status": "SUBMITTED", "tx_hash": tx_hash}
                save_json(CHECKPOINT_PATH, state)
    return_code = process.wait()
    if return_code != 0:
        precheck = re.search(r"EVM tx (0x[0-9a-fA-F]{64})", "".join(output))
        if precheck:
            state["transactions"].append({
                "step": step + "_fee_precheck", "method": method, "signer": signer.lower(),
                "args": args, "hash": precheck.group(1), "explorer": EXPLORER + precheck.group(1),
                "consensus_status": "REJECTED_BEFORE_CONTRACT", "execution_result": "FEE_VALIDATION_ERROR",
                "error": "FeeValueMustBeNonZero",
            })
        state["status"] = "FAIL"
        save_json(CHECKPOINT_PATH, state)
        raise LiveBlocker(f"{method} failed: {''.join(output)[-2000:]}")
    if not tx_hash:
        raise LiveBlocker(f"{method} returned no transaction hash")
    tx = next(item for item in state["transactions"] if item["hash"] == tx_hash)
    status, result = receipt_outcome(tx_hash)
    if status != "FINALIZED" or result != "FINISHED_WITH_RETURN":
        tx["consensus_status"] = status
        tx["execution_result"] = result
        state["status"] = "FAIL"
        save_json(CHECKPOINT_PATH, state)
        raise LiveBlocker(f"{method} did not finalize with successful execution")
    tx["consensus_status"] = status
    tx["execution_result"] = result
    state["steps"][step] = {"status": "PASS", "tx_hash": tx_hash}
    state["last_verified_checkpoint"] = step
    save_json(CHECKPOINT_PATH, state)
    return state["steps"][step]


def expect(state: dict[str, Any], label: str, actual: Any, expected: Any) -> None:
    passed = actual == expected
    state["assertions"].append({"label": label, "passed": passed, "actual": actual, "expected": expected})
    save_json(CHECKPOINT_PATH, state)
    if not passed:
        raise LiveBlocker(f"assertion failed: {label}: {actual!r} != {expected!r}")


def save_value(state: dict[str, Any], key: str, value: Any) -> None:
    state["values"][key] = value
    save_json(CHECKPOINT_PATH, state)


def write_outputs(state: dict[str, Any], status: str) -> None:
    state["status"] = status
    save_json(CHECKPOINT_PATH, state)
    evidence = {
        "contract": state["contract"], "network": state["network"], "chain_id": state["chain_id"],
        "wallets": state["wallets"], "values": state["values"], "transactions": state["transactions"],
        "assertions": state["assertions"], "status": state["status"],
    }
    save_json(EVIDENCE_PATH, evidence)
    lines = [
        "# SLATE Studio Dev live-test report", "", f"- Status: **{status}**",
        f"- Contract: `{state['contract']}`", f"- Network: `{state['network']}` / chain `{state['chain_id']}`", "",
        "## Wallets", "",
    ]
    for label, address in state["wallets"].items():
        lines.append(f"- {label}: `{address}`")
    lines += ["", "## Transactions", "", "| Step | Method | Signer | Hash | Consensus | Execution |", "|---|---|---|---|---|---|"]
    for tx in state["transactions"]:
        lines.append(f"| {tx['step']} | {tx['method']} | `{tx['signer']}` | [`{tx['hash']}`]({tx['explorer']}) | {tx['consensus_status']} | {tx['execution_result']} |")
    lines += ["", "## Assertions", ""]
    for item in state["assertions"]:
        lines.append(f"- [{'x' if item['passed'] else ' '}] {item['label']}: `{item['actual']}`")
    lines += ["", "This evidence contains no private keys, mnemonics, passwords, or raw receipts.", ""]
    REPORT_PATH.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    config = load_json(CONFIG_PATH, None)
    if not config:
        raise LiveBlocker(f"missing {CONFIG_PATH}")
    state = checkpoint(config)
    try:
        wallets = load_json(RESULTS / "wallets.json", None)
        if not wallets:
            raise LiveBlocker("wallets.json is missing; run setup-wallets.exp with secure interactive prompts first")
        names = config["wallet_names"]
        state["wallets"] = {
            "wallet_a": wallets[names["owner_agent_reviewer1"]],
            "wallet_b": wallets[names["reviewer2"]],
            "wallet_c": wallets[names["reviewer3"]],
        }
        if len(set(state["wallets"].values())) != 3:
            raise LiveBlocker("test wallet addresses are not pairwise distinct")
        save_json(CHECKPOINT_PATH, state)
        verify_network(config)
        scenario = config["scenario"]
        owner, reviewer2, reviewer3 = state["wallets"]["wallet_a"], state["wallets"]["wallet_b"], state["wallets"]["wallet_c"]

        org_id = state["values"].get("organization_id")
        if not org_id:
            use_wallet(names["owner_agent_reviewer1"], owner)
            existing = read_call(config, "get_my_latest_organization")
            if existing:
                raise LiveBlocker(f"dedicated owner wallet already has organization {existing}; refusing to create a duplicate")
            run_write(config, state, "create_organization", "create_organization", names["owner_agent_reviewer1"], owner,
                      [scenario["organization_name"], scenario["initial_policy"], owner, owner, reviewer2, reviewer3])
            org_id = read_call(config, "get_my_latest_organization")
            if not isinstance(org_id, str) or not org_id.startswith("org-"):
                raise LiveBlocker("create_organization did not expose an org- identifier")
            save_value(state, "organization_id", org_id)
        organization = read_call(config, "get_organization", org_id)
        expect(state, "owner is Wallet A", organization["owner"], owner.lower())
        expect(state, "agent is Wallet A", organization["agent"], owner.lower())
        if organization["active_version"] == 1:
            expect(state, "active version is 1", organization["active_version"], 1)
        elif organization["active_version"] == 2 and state["steps"].get("activate_amendment", {}).get("status") == "PASS":
            expect(state, "active version is 2 after checkpointed activation", organization["active_version"], 2)
        else:
            raise LiveBlocker(f"unexpected active version for resume: {organization['active_version']}")
        reviewers = read_call(config, "get_reviewers", org_id)
        expect(state, "reviewer set", reviewers, {"organization_id": org_id, "reviewer_1": owner.lower(), "reviewer_2": reviewer2.lower(), "reviewer_3": reviewer3.lower()})
        save_value(state, "policy_v1", read_call(config, "get_policy_version", org_id, "1"))

        rid = state["values"].get("resource_id") or resource_id(org_id, scenario["resource_key"], scenario["resource_description"])
        run_write(config, state, "register_resource", "register_resource", names["owner_agent_reviewer1"], owner,
                  [org_id, scenario["resource_key"], scenario["resource_description"]])
        resource = read_call(config, "get_resource", rid)
        expect(state, "resource starts disabled", resource["enabled"], False)
        save_value(state, "resource_id", rid)

        policy_v1 = state["values"]["policy_v1"]
        action1 = action_id(org_id, 1, {"active_agent": owner.lower(), "active_policy_id": policy_v1["policy_id"], "version": 1, "active_policy_digest": policy_v1["policy_digest"]}, resource, True, scenario["purpose"])
        run_write(config, state, "action_v1_deny", "apply_agent_action", names["owner_agent_reviewer1"], owner,
                  [org_id, rid, "true", scenario["purpose"]])
        denied = read_call(config, "get_action", action1)
        expect(state, "V1 decision is DENY", denied["semantic_status"], "DENY")
        expect(state, "V1 action uses policy version 1", denied["active_policy_version"], 1)
        expect(state, "V1 denial leaves resource disabled", read_call(config, "get_resource_enabled", rid), False)
        save_value(state, "action_v1", denied)

        org = read_call(config, "get_organization", org_id)
        proposed = scenario["proposed_policy"]
        amd = state["values"].get("amendment_id") or amendment_id(
            org_id, org["amendment_count"] + 1,
            proposed_digest(org_id, 1, proposed), scenario["rationale"],
        )
        run_write(config, state, "propose_amendment", "propose_amendment", names["owner_agent_reviewer1"], owner,
                  [org_id, proposed, scenario["rationale"]])
        pending = read_call(config, "get_pending_amendment", org_id)
        expected_pending = "" if state["steps"].get("activate_amendment", {}).get("status") == "PASS" else amd
        expect(state, "pending amendment checkpoint", pending, expected_pending)
        save_value(state, "amendment_id", amd)
        run_write(config, state, "classify_amendment", "classify_amendment", names["owner_agent_reviewer1"], owner, [amd])
        amendment = read_call(config, "get_amendment", amd)
        expect(state, "amendment classification is EXPANDS", amendment["classification"], "EXPANDS")
        expect(state, "expansion threshold is 3", read_call(config, "get_required_approvals", amd), 3)
        if state["steps"].get("activate_amendment", {}).get("status") == "PASS":
            expect(state, "amendment remains ACTIVATED on resume", amendment["status"], "ACTIVATED")
        else:
            expect(state, "amendment is CLASSIFIED", amendment["status"], "CLASSIFIED")

        for step, name, address in (("vote_reviewer_1", names["owner_agent_reviewer1"], owner), ("vote_reviewer_2", names["reviewer2"], reviewer2), ("vote_reviewer_3", names["reviewer3"], reviewer3)):
            run_write(config, state, step, "vote_amendment", name, address, [amd, "true"])
            vote = read_call(config, "get_amendment_vote", amd, address)
            expect(state, f"{step} approval persisted", vote["approve"], True)
            if step == "vote_reviewer_2":
                status_after_two = "ACTIVATED" if state["steps"].get("activate_amendment", {}).get("status") == "PASS" else "CLASSIFIED"
                expect(state, "two approvals checkpoint status", read_call(config, "get_amendment", amd)["status"], status_after_two)
        final_vote_status = "ACTIVATED" if state["steps"].get("activate_amendment", {}).get("status") == "PASS" else "READY"
        expect(state, "three approvals checkpoint status", read_call(config, "get_amendment", amd)["status"], final_vote_status)

        run_write(config, state, "activate_amendment", "activate_amendment", names["owner_agent_reviewer1"], owner, [amd])
        active = read_call(config, "get_active_policy", org_id)
        expect(state, "active policy version is 2", active["version"], 2)
        expect(state, "policy version 1 remains immutable", read_call(config, "get_policy_version", org_id, "1")["policy"], scenario["initial_policy"])
        expect(state, "amendment is ACTIVATED", read_call(config, "get_amendment", amd)["status"], "ACTIVATED")
        expect(state, "pending amendment is cleared", read_call(config, "get_pending_amendment", org_id), "")
        save_value(state, "policy_v2", active)

        resource = read_call(config, "get_resource", rid)
        action2 = action_id(org_id, 2, {"active_agent": owner.lower(), "active_policy_id": active["policy_id"], "version": 2, "active_policy_digest": active["policy_digest"]}, resource, True, scenario["purpose"])
        run_write(config, state, "action_v2_allow", "apply_agent_action", names["owner_agent_reviewer1"], owner,
                  [org_id, rid, "true", scenario["purpose"]])
        allowed = read_call(config, "get_action", action2)
        expect(state, "V2 decision is ALLOW", allowed["semantic_status"], "ALLOW")
        expect(state, "V2 action uses policy version 2", allowed["active_policy_version"], 2)
        expect(state, "V2 ALLOW enables resource", read_call(config, "get_resource_enabled", rid), True)
        save_value(state, "action_v2", allowed)
        write_outputs(state, "PASS")
        return 0
    except LiveBlocker as error:
        write_outputs(state, "BLOCKED")
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        write_outputs(state, "FAIL")
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
