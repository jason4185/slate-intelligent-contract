import json
import sys
import types

import pytest


class UserError(Exception):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class TreeMap(dict):
    pass


class Address:
    def __init__(self, value):
        if isinstance(value, str):
            self._as_bytes = bytes.fromhex(value[2:])
        else:
            self._as_bytes = bytes(value)

    @property
    def as_bytes(self):
        return self._as_bytes

    @property
    def as_hex(self):
        return "0x" + self._as_bytes.hex()


class Public:
    @staticmethod
    def write(function):
        return function

    @staticmethod
    def view(function):
        return function


class Contract:
    pass


class VM:
    UserError = UserError
    Return = Return

    @staticmethod
    def run_nondet(leader, validator):
        result = leader()
        if not validator(Return(result)):
            raise UserError("semantic consensus rejected")
        return result


class Message:
    sender_address = "0x" + "00" * 20


class Nondet:
    response = {"status": "UNRESOLVED"}

    @classmethod
    def exec_prompt(cls, prompt, response_format="json"):
        return cls.response


genlayer_stub = types.ModuleType("genlayer")
genlayer_stub.contract = types.SimpleNamespace(Contract=Contract)
genlayer_stub.public = Public()
genlayer_stub.vm = VM()
genlayer_stub.message = Message()
genlayer_stub.nondet = Nondet()
types_stub = types.ModuleType("genlayer.types")
types_stub.Address = Address
types_stub.u256 = int
storage_stub = types.ModuleType("genlayer.storage")
storage_stub.TreeMap = TreeMap
sys.modules["genlayer"] = genlayer_stub
sys.modules["genlayer.types"] = types_stub
sys.modules["genlayer.storage"] = storage_stub

from contracts.Slate import (  # noqa: E402
    ALLOW,
    CLASSIFIED,
    DENY,
    EQUIVALENT,
    EXPANDS,
    INVALID,
    MAX_ACTIONS_PER_ORG,
    MAX_AMENDMENTS_PER_ORG,
    MAX_POLICY_VERSIONS,
    MAX_PROMPT_BYTES,
    REJECTED,
    RESTRICTS,
    READY,
    Slate,
    UNRESOLVED,
    _action_prompt,
    _action_snapshot,
    _amendment_prompt,
    _amendment_snapshot,
)


OWNER = "0x" + "11" * 20
OWNER_2 = "0x" + "12" * 20
AGENT = "0x" + "21" * 20
REVIEWER_1 = "0x" + "31" * 20
REVIEWER_2 = "0x" + "32" * 20
REVIEWER_3 = "0x" + "33" * 20
OTHER_1 = "0x" + "41" * 20
OTHER_2 = "0x" + "42" * 20
OTHER_3 = "0x" + "43" * 20
STUDIO_AGENT_INT = 1145954250134493008813711703336885790074517134215
STUDIO_REVIEWER_2_INT = 602484852368848266390175755014502971560912933655
STUDIO_REVIEWER_3_INT = 872276343296180473360003249987088011432764122653
STUDIO_AGENT_HEX = "0xc8ba5da455b011863f2eca76a6fa21e62cc91b87"
STUDIO_REVIEWER_2_HEX = "0x69885aeb09f8cb62fff8b2224c66791bfcaed317"
STUDIO_REVIEWER_3_HEX = "0x98ca3958c05f6e4b53ae8d66af750f51d540261d"


def new_contract():
    contract = Slate()
    for name in (
        "organization_records", "policy_version_records", "resource_records",
        "resource_key_index", "amendment_records", "amendment_vote_records",
        "action_records", "pending_amendment_by_org", "latest_org_by_owner",
    ):
        setattr(contract, name, TreeMap())
    return contract


def sender(address):
    genlayer_stub.message.sender_address = address


def expect_error(function):
    with pytest.raises(UserError):
        function()


def create_org(contract, owner=OWNER, policy="agent may enable internal monitoring resources"):
    sender(owner)
    return contract.create_organization(
        "Acme Operations", policy, AGENT, REVIEWER_1, REVIEWER_2, REVIEWER_3
    )


def register(contract, org, key="internal", description="Internal monitoring"):
    sender(OWNER)
    return contract.register_resource(org, key, description)


def propose_and_classify(contract, org, proposed, classification):
    sender(OWNER)
    amendment = contract.propose_amendment(org, proposed, "Operational policy update")
    Nondet.response = {"status": CLASSIFIED, "classification": classification}
    assert contract.classify_amendment(amendment) == CLASSIFIED
    return amendment


def vote(contract, amendment, reviewer, approve=True):
    sender(reviewer)
    contract.vote_amendment(amendment, approve)


def test_creation_version_one_reviewers_and_resource_state():
    contract = new_contract()
    org = create_org(contract)
    organization = json.loads(contract.get_organization(org))
    policy = json.loads(contract.get_active_policy(org))
    assert organization["owner"] == OWNER
    assert organization["agent"] == AGENT
    assert organization["active_version"] == 1
    assert policy["version"] == 1
    assert contract.get_reviewers(org) == json.dumps({
        "organization_id": org, "reviewer_1": REVIEWER_1,
        "reviewer_2": REVIEWER_2, "reviewer_3": REVIEWER_3,
    }, separators=(",", ":"), sort_keys=True)
    resource = register(contract, org)
    assert contract.get_resource_enabled(resource) is False
    expect_error(lambda: contract.create_organization(
        "Bad", "policy", AGENT, REVIEWER_1, REVIEWER_1, REVIEWER_3
    ))
    expect_error(lambda: register(contract, org, "internal", "Duplicate key"))


def test_studio_integer_addresses_create_org_and_preserve_version_one():
    contract = new_contract()
    sender(Address(OWNER))
    org = contract.create_organization(
        "Studio Operations", "agent may enable monitoring",
        STUDIO_AGENT_INT, STUDIO_AGENT_INT,
        STUDIO_REVIEWER_2_INT, STUDIO_REVIEWER_3_INT,
    )
    organization = json.loads(contract.get_organization(org))
    assert organization["agent"] == STUDIO_AGENT_HEX
    assert organization["reviewer_1"] == STUDIO_AGENT_HEX
    assert organization["reviewer_2"] == STUDIO_REVIEWER_2_HEX
    assert organization["reviewer_3"] == STUDIO_REVIEWER_3_HEX
    assert len({organization["reviewer_1"], organization["reviewer_2"], organization["reviewer_3"]}) == 3
    assert json.loads(contract.get_policy_version(org, 1))["version"] == 1
    assert contract.get_latest_organization_for_owner(int(OWNER, 16)) == org


def test_canonical_addresses_support_native_bytes_and_exact_reviewer_votes():
    contract = new_contract()
    sender(Address(OWNER))
    org = contract.create_organization(
        "Canonical Operations", "agent may enable monitoring",
        Address(STUDIO_AGENT_HEX), Address(STUDIO_AGENT_HEX),
        bytes.fromhex(STUDIO_REVIEWER_2_HEX[2:]),
        Address(STUDIO_REVIEWER_3_HEX),
    )
    sender(OWNER)
    amendment = contract.propose_amendment(org, "agent may enable more monitoring", "expand")
    Nondet.response = {"status": CLASSIFIED, "classification": EXPANDS}
    contract.classify_amendment(amendment)
    vote(contract, amendment, STUDIO_AGENT_INT, True)
    vote(contract, amendment, STUDIO_REVIEWER_2_INT, True)
    vote(contract, amendment, STUDIO_REVIEWER_3_INT, True)
    assert json.loads(contract.get_amendment(amendment))["status"] == READY
    assert json.loads(contract.get_amendment_vote(amendment, STUDIO_AGENT_INT))["approve"] is True
    assert json.loads(contract.get_amendment_vote(amendment, STUDIO_REVIEWER_2_INT))["approve"] is True


@pytest.mark.parametrize(
    "bad_agent",
    [
        0,
        -1,
        1 << 160,
        b"short",
        b"x" * 21,
        "0x1234",
        "1234567890abcdef1234567890abcdef12345678",
        "0xgg" + "0" * 38,
        object(),
    ],
)
def test_invalid_address_representations_are_rejected(bad_agent):
    contract = new_contract()
    sender(OWNER)
    expect_error(lambda: contract.create_organization(
        "Invalid Address", "policy", bad_agent,
        REVIEWER_1, REVIEWER_2, REVIEWER_3,
    ))


def test_duplicate_addresses_are_rejected_after_normalization():
    contract = new_contract()
    sender(OWNER)
    expect_error(lambda: contract.create_organization(
        "Duplicate Address", "policy", AGENT,
        STUDIO_AGENT_HEX.upper(), STUDIO_AGENT_INT,
        REVIEWER_3,
    ))


def test_multi_organization_isolation_and_authorization():
    contract = new_contract()
    org_a = create_org(contract, OWNER)
    sender(OWNER_2)
    org_b = contract.create_organization(
        "Second Operations", "agent may enable customer notifications",
        AGENT, OTHER_1, OTHER_2, OTHER_3
    )
    resource_a = register(contract, org_a)
    sender(OWNER_2)
    resource_b = contract.register_resource(org_b, "customer", "Customer notifications")
    sender(OWNER)
    expect_error(lambda: contract.register_resource(org_b, "wrong-owner", "x"))
    expect_error(lambda: contract.propose_amendment(org_b, "policy", "x"))
    sender(AGENT)
    Nondet.response = {"status": DENY}
    expect_error(lambda: contract.apply_agent_action(org_b, resource_a, True, "cross org"))
    assert contract.get_resource_enabled(resource_a) is False
    assert contract.get_resource_enabled(resource_b) is False
    assert contract.get_latest_organization_for_owner(OWNER) == org_a
    sender(OWNER)
    assert contract.get_my_latest_organization() == org_a


def test_amendment_pending_slot_and_strict_classification_outcomes():
    contract = new_contract()
    org = create_org(contract)
    sender(OWNER)
    first = contract.propose_amendment(org, "agent may enable monitoring and alerts", "expand")
    expect_error(lambda: contract.propose_amendment(org, "another policy", "blocked"))
    Nondet.response = {"status": CLASSIFIED, "classification": EXPANDS}
    assert contract.classify_amendment(first) == CLASSIFIED
    assert contract.get_required_approvals(first) == 3
    expect_error(lambda: contract.classify_amendment(first))
    contract.cancel_amendment(first)
    assert json.loads(contract.get_amendment(first))["status"] == "CANCELLED"
    assert contract.get_pending_amendment(org) == ""

    second = propose_and_classify(contract, org, "agent may enable fewer resources", RESTRICTS)
    assert contract.get_required_approvals(second) == 2
    sender(OWNER)
    contract.cancel_amendment(second)
    third = contract.propose_amendment(org, "same authority, clearer wording", "clarify")
    Nondet.response = {"status": CLASSIFIED, "classification": EQUIVALENT}
    assert contract.classify_amendment(third) == CLASSIFIED
    assert contract.get_required_approvals(third) == 2


def test_invalid_and_unresolved_release_pending_slot():
    contract = new_contract()
    org = create_org(contract)
    sender(OWNER)
    invalid = contract.propose_amendment(org, "the owner may change thresholds", "bad boundary")
    Nondet.response = {"status": INVALID}
    assert contract.classify_amendment(invalid) == INVALID
    assert contract.get_pending_amendment(org) == ""
    unresolved = contract.propose_amendment(org, "unclear policy", "unclear")
    Nondet.response = {"status": UNRESOLVED}
    assert contract.classify_amendment(unresolved) == UNRESOLVED
    assert contract.get_pending_amendment(org) == ""


def test_malformed_amendment_response_keeps_proposal_usable():
    contract = new_contract()
    org = create_org(contract)
    sender(OWNER)
    amendment = contract.propose_amendment(org, "agent may enable alerts", "bad model")
    Nondet.response = '{"status":"CLASSIFIED","classification":"EXPANDS","extra":1}'
    expect_error(lambda: contract.classify_amendment(amendment))
    assert json.loads(contract.get_amendment(amendment))["status"] == "PROPOSED"
    assert contract.get_pending_amendment(org) == amendment


def test_independent_validator_disagreement_rejects_without_persistence():
    contract = new_contract()
    org = create_org(contract)
    sender(OWNER)
    amendment = contract.propose_amendment(
        org, "agent may enable alerts", "validator disagreement"
    )
    responses = [
        {"status": CLASSIFIED, "classification": EXPANDS},
        {"status": CLASSIFIED, "classification": RESTRICTS},
    ]
    original = Nondet.__dict__["exec_prompt"]

    def disagree(cls, prompt, response_format="json"):
        return responses.pop(0)

    Nondet.exec_prompt = classmethod(disagree)
    try:
        expect_error(lambda: contract.classify_amendment(amendment))
    finally:
        Nondet.exec_prompt = original
    assert json.loads(contract.get_amendment(amendment))["status"] == "PROPOSED"
    assert contract.get_pending_amendment(org) == amendment


def test_action_validator_disagreement_rejects_without_state_change():
    contract = new_contract()
    org = create_org(contract)
    resource = register(contract, org)
    sender(AGENT)
    responses = [{"status": ALLOW}, {"status": DENY}]
    original = Nondet.__dict__["exec_prompt"]

    def disagree(cls, prompt, response_format="json"):
        return responses.pop(0)

    Nondet.exec_prompt = classmethod(disagree)
    try:
        expect_error(lambda: contract.apply_agent_action(
            org, resource, True, "validator disagreement"
        ))
    finally:
        Nondet.exec_prompt = original
    assert contract.get_resource_enabled(resource) is False
    assert contract.action_count == 0


def test_rejected_terminal_amendment_releases_slot_and_cannot_reopen():
    contract = new_contract()
    org = create_org(contract)
    amendment = propose_and_classify(contract, org, "expanded policy", EXPANDS)
    vote(contract, amendment, REVIEWER_1, False)
    assert json.loads(contract.get_amendment(amendment))["status"] == REJECTED
    assert contract.get_pending_amendment(org) == ""
    expect_error(lambda: vote(contract, amendment, REVIEWER_2, True))
    sender(OWNER)
    replacement = contract.propose_amendment(org, "replacement policy", "retry")
    assert replacement != amendment


def test_prompt_builders_bound_maximum_utf8_inputs_after_json_escaping():
    contract_owner = OWNER
    contract = new_contract()
    org_id = create_org(contract, contract_owner, policy='policy "with" \\ escapes')
    organization = json.loads(contract.get_organization(org_id))
    policy = json.loads(contract.get_active_policy(org_id))
    amendment_snapshot = _amendment_snapshot(
        organization, policy, "é" * 800, "line\nquote\"\\" * 80
    )
    action_resource = json.loads(
        contract.get_resource(register(contract, org_id, "notify", "Customer \\ alerts"))
    )
    action_snapshot = _action_snapshot(
        organization, policy, action_resource, True, "purpose\nquote\"\\" * 80
    )
    amendment_prompt = _amendment_prompt(amendment_snapshot)
    action_prompt = _action_prompt(action_snapshot)
    assert len(amendment_prompt.encode("utf-8")) <= MAX_PROMPT_BYTES
    assert len(action_prompt.encode("utf-8")) <= MAX_PROMPT_BYTES


def test_invalid_addresses_and_full_amendment_version_capacity():
    contract = new_contract()
    sender(OWNER)
    expect_error(lambda: contract.create_organization(
        "Invalid", "policy", "0x" + "00" * 20, REVIEWER_1, REVIEWER_2, REVIEWER_3
    ))
    org = create_org(contract)
    for version in range(2, MAX_POLICY_VERSIONS + 1):
        amendment = propose_and_classify(
            contract, org, "agent may enable resource version " + str(version), EXPANDS
        )
        vote(contract, amendment, REVIEWER_1, True)
        vote(contract, amendment, REVIEWER_2, True)
        vote(contract, amendment, REVIEWER_3, True)
        contract.activate_amendment(amendment)
    assert json.loads(contract.get_active_policy(org))["version"] == MAX_POLICY_VERSIONS
    assert json.loads(contract.get_organization(org))["amendment_count"] == MAX_AMENDMENTS_PER_ORG
    expect_error(lambda: contract.propose_amendment(org, "ninth amendment", "capacity"))


@pytest.mark.parametrize(
    "classification, votes, final_status",
    [
        (EXPANDS, [True, True, True], READY),
        (EXPANDS, [True, True, False], REJECTED),
        (RESTRICTS, [True, True], READY),
        (RESTRICTS, [False, True, True], READY),
        (RESTRICTS, [False, False], REJECTED),
        (EQUIVALENT, [True, True], READY),
    ],
)
def test_exact_reviewer_thresholds(classification, votes, final_status):
    contract = new_contract()
    org = create_org(contract)
    amendment = propose_and_classify(contract, org, "new authority policy", classification)
    reviewers = [REVIEWER_1, REVIEWER_2, REVIEWER_3]
    for index, decision in enumerate(votes):
        vote(contract, amendment, reviewers[index], decision)
    record = json.loads(contract.get_amendment(amendment))
    assert record["status"] == final_status
    if final_status == READY:
        expect_error(lambda: vote(contract, amendment, REVIEWER_3, True))


def test_duplicate_nonreviewer_votes_and_activation_integrity():
    contract = new_contract()
    org = create_org(contract)
    amendment = propose_and_classify(contract, org, "expanded authority", EXPANDS)
    expect_error(lambda: vote(contract, amendment, OTHER_1, True))
    vote(contract, amendment, REVIEWER_1, True)
    expect_error(lambda: vote(contract, amendment, REVIEWER_1, True))
    expect_error(lambda: contract.activate_amendment(amendment))
    vote(contract, amendment, REVIEWER_2, True)
    vote(contract, amendment, REVIEWER_3, True)
    assert json.loads(contract.get_amendment(amendment))["status"] == READY
    sender(OTHER_1)
    new_policy = contract.activate_amendment(amendment)
    assert json.loads(contract.get_active_policy(org))["version"] == 2
    assert contract.get_policy_version(org, 1) != contract.get_policy_version(org, 2)
    assert json.loads(contract.get_amendment(amendment))["status"] == "ACTIVATED"
    assert contract.get_pending_amendment(org) == ""
    expect_error(lambda: contract.activate_amendment(amendment))
    assert new_policy == json.loads(contract.get_active_policy(org))["policy_id"]


def test_action_allow_deny_unresolved_and_policy_version_binding():
    contract = new_contract()
    org = create_org(contract, policy="agent may enable internal monitoring resources")
    internal = register(contract, org, "monitor", "Internal monitoring")
    customer = register(contract, org, "notify", "Customer-facing notifications")
    sender(AGENT)
    Nondet.response = {"status": DENY}
    denied = contract.apply_agent_action(org, customer, True, "enable notifications")
    assert contract.get_resource_enabled(customer) is False
    assert json.loads(contract.get_action(denied))["active_policy_version"] == 1
    Nondet.response = {"status": UNRESOLVED}
    unresolved = contract.apply_agent_action(org, internal, True, "unclear purpose")
    assert contract.get_resource_enabled(internal) is False
    assert json.loads(contract.get_action(unresolved))["semantic_status"] == UNRESOLVED
    Nondet.response = {"status": ALLOW}
    allowed = contract.apply_agent_action(org, internal, True, "enable monitoring")
    assert contract.get_resource_enabled(internal) is True
    assert json.loads(contract.get_action(allowed))["enabled_after"] is True
    expect_error(lambda: contract.apply_agent_action(org, internal, True, "no-op"))
    sender(OWNER)
    amendment = propose_and_classify(contract, org, "agent may enable customer-facing notifications", EXPANDS)
    vote(contract, amendment, REVIEWER_1, True)
    vote(contract, amendment, REVIEWER_2, True)
    vote(contract, amendment, REVIEWER_3, True)
    contract.activate_amendment(amendment)
    sender(AGENT)
    Nondet.response = {"status": ALLOW}
    action = contract.apply_agent_action(org, customer, True, "approved operational notification")
    record = json.loads(contract.get_action(action))
    assert contract.get_resource_enabled(customer) is True
    assert record["active_policy_version"] == 2


def test_atlas_policy_upgrade_changes_enforced_resource_state():
    contract = new_contract()
    sender(OWNER)
    org = contract.create_organization(
        "Atlas Operations",
        "The authorized agent may enable internal monitoring resources. "
        "The agent must not enable customer-facing notification resources.",
        AGENT, REVIEWER_1, REVIEWER_2, REVIEWER_3,
    )
    monitoring = register(contract, org, "monitoring", "Internal monitoring")
    notifications = register(
        contract, org, "notifications", "Customer-facing notifications"
    )

    sender(AGENT)
    Nondet.response = {"status": DENY}
    first_action = contract.apply_agent_action(
        org, notifications, True, "enable customer notifications"
    )
    assert contract.get_resource_enabled(notifications) is False
    assert json.loads(contract.get_action(first_action))["active_policy_version"] == 1

    sender(OWNER)
    amendment = contract.propose_amendment(
        org,
        "The authorized agent may enable internal monitoring resources and "
        "may also enable customer-facing notification resources for approved "
        "operational use.",
        "approved operational use",
    )
    Nondet.response = {"status": CLASSIFIED, "classification": EXPANDS}
    assert contract.classify_amendment(amendment) == CLASSIFIED
    assert contract.get_required_approvals(amendment) == 3
    vote(contract, amendment, REVIEWER_1, True)
    vote(contract, amendment, REVIEWER_2, True)
    assert json.loads(contract.get_amendment(amendment))["status"] != READY
    vote(contract, amendment, REVIEWER_3, True)
    assert json.loads(contract.get_amendment(amendment))["status"] == READY
    sender(OTHER_1)
    contract.activate_amendment(amendment)

    assert json.loads(contract.get_active_policy(org))["version"] == 2
    assert json.loads(contract.get_policy_version(org, 1))["policy"].startswith(
        "The authorized agent may enable internal monitoring resources."
    )
    assert contract.get_pending_amendment(org) == ""

    sender(AGENT)
    Nondet.response = {"status": ALLOW}
    second_action = contract.apply_agent_action(
        org, notifications, True, "approved operational notification"
    )
    assert contract.get_resource_enabled(notifications) is True
    second_record = json.loads(contract.get_action(second_action))
    assert second_record["resource_id"] == notifications
    assert second_record["active_policy_version"] == 2
    assert contract.get_resource_enabled(monitoring) is False


def test_malformed_semantics_and_cross_resource_side_effects_rollback():
    contract = new_contract()
    org = create_org(contract)
    resource = register(contract, org)
    sender(AGENT)
    Nondet.response = '{"status":"ALLOW","extra":1}'
    expect_error(lambda: contract.apply_agent_action(org, resource, True, "malformed"))
    assert contract.get_resource_enabled(resource) is False
    assert contract.action_count == 0
    Nondet.response = '{"status":"ALLOW","status":"DENY"}'
    expect_error(lambda: contract.apply_agent_action(org, resource, True, "duplicate keys"))
    assert contract.get_resource_enabled(resource) is False


def test_maximum_bounds_and_action_history_are_real_contract_state():
    contract = new_contract()
    org = create_org(contract)
    for index in range(4):
        register(contract, org, "r" + str(index), "resource " + str(index))
    expect_error(lambda: register(contract, org, "overflow", "resource overflow"))
    sender(AGENT)
    for index in range(MAX_ACTIONS_PER_ORG):
        resource_id = list(contract.resource_records.keys())[index % 4]
        desired = index % 2 == 0
        if contract.get_resource_enabled(resource_id) == desired:
            desired = not desired
        Nondet.response = {"status": DENY}
        contract.apply_agent_action(org, resource_id, desired, "bounded action " + str(index))
    expect_error(lambda: contract.apply_agent_action(org, resource_id, not desired, "overflow"))
    assert contract.action_count == MAX_ACTIONS_PER_ORG


def test_identifier_and_record_views_do_not_fabricate_missing_votes():
    contract = new_contract()
    org = create_org(contract)
    amendment = propose_and_classify(contract, org, "restricted authority", RESTRICTS)
    assert contract.get_amendment_vote(amendment, REVIEWER_1) == ""
    expect_error(lambda: contract.get_amendment_vote(amendment, OTHER_1))
    expect_error(lambda: contract.get_resource("rsc-" + "0" * 64))
    expect_error(lambda: contract.get_policy_version(org, MAX_POLICY_VERSIONS))
