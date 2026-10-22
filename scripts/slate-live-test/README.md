# SLATE Studio Dev live test

This runner uses the installed `genlayer` CLI against the already deployed
Studio Dev contract. It does not deploy, modify `contracts/Slate.py`, or use
mocked semantic responses.

The wallet setup uses CLI interactive password prompts and the macOS keychain.
It never writes private keys, mnemonics, or passwords into this project.

## First run

From the project root:

```sh
expect scripts/slate-live-test/setup-wallets.exp
python3 scripts/slate-live-test/run_live_test.py
```

The setup script refuses to overwrite an existing account. The runner expects
the three names created by the setup script and checks their active addresses
before every write. It records only public addresses, transaction hashes,
receipt outcomes, and read-back state in `results/`.

If a transaction is submitted but the process stops before its outcome is
known, the runner records the hash and blocks rather than resubmitting it.
Resume with the same command after inspecting or completing that transaction.

The CLI must be on the `studio-dev` profile. The runner verifies chain ID
61997 and the canonical RPC before sending anything.
