# Vanguard

A demo-grade authorization platform for sensitive actions such as vault transfers. Approvals require a passkey (WebAuthn) and a second-device check through a QR handshake. It also includes a small, advisory AI analyzer for approval requests.

> **Status:** personal project, not production-ready. State is held in memory, and several known issues are listed below.

## What it does

- **Passkey sign-in and registration** using WebAuthn, with privileged approver roles provisioned through single-use admin invites.
- **Vault approval flow:** the requester creates a `VAULT_TRANSFER` request. The primary approver (or a backup) decides on one device, and a second device confirms the decision by scanning a QR code and completing a passkey check.
- **Audit ledger:** each passkey-verified action writes a receipt to SQLite (`vanguard_audit.db`).
- **Advisory analyzer (`ai_analyzer.py`):** deterministic rules plus a local model add a note to each approval. The note never changes the approval outcome.

## Known limitations

- **In-memory state.** Sessions, approvals, and QR handshakes live in Python dictionaries. Restarting the server (including `--reload` on file save) clears them.
- **Receipts are written too early.** The ledger entry is created during the passkey check, before the decision completes. A receipt can therefore exist for an approval that never finished. The fix is to write the receipt inside the decision handler after the status changes.
- **The step-up TOTP code is generated in the browser.** The six-digit code shown in the QR dialog comes from a secret held by the same browser that makes the decision. For a stronger design, the code should come only from the approver's phone.
- **Cancelling clears the handshake.** Cancel discards the session on the requesting device, so the decision cannot complete afterward.
- **Minor:** the logo file `vanguard-logo.svg` is not served, so the page logs a 404.

## AI analyzer: results

`ai_analyzer.py` combines two checks:

1. **Rules (code):** off-hours (00:00–05:59), any amount other than $50,000, any target other than `Escrow Node 09`, any asset other than USDC, and more than 3 approvals in the last hour.
2. **Local model (`qwen2.5:1.5b` via Ollama, temperature 0):** asked for an independent verdict with no rule list.

Evaluation on 55 labeled approvals (`labeled_cases.json` and `labeled_cases_extra.json`, labels written from `LABELING_RULES.md`):

| Approach | Precision | Recall | Parse failures |
|---|---|---|---|
| Rules only | 1.00 | 0.57 | — |
| Local model only | 0.00 | 0.00 | 0/55 |
| Combined (advisory) | 1.00 | 0.57 | — |

Interpretation:
- All detections come from the rules. The model flagged none of the 30 positive cases, including all 13 judgment cases.
- The model's reasons assumed a typical transfer amount, which this vault does not use.
- The analyzer is therefore advisory only. The outcome is decided by the rules, and the model's note is displayed separately.

Limitations of this evaluation:
- Labels were written by the author, and some judgment cases are arguable.
- The judgment cases vary only the requester name.
- One small model and one prompt were tested. A larger model or a policy-aware prompt could give different results.

## Running it

Requirements: Python 3.9+, and [Ollama](https://ollama.com) if you want the model note.

```bash
python3 -m venv venv
./venv/bin/python3 -m pip install fastapi uvicorn pyotp webauthn ollama
./venv/bin/python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

For the model note, run `ollama pull qwen2.5:1.5b` first. If Ollama is not running, the approval still works and the note shows an error.

To reproduce the evaluation:

```bash
./venv/bin/python3 evaluate.py
```

## Configuration

| Variable | Purpose |
|---|---|
| `ADMIN_BOOTSTRAP_SECRET` | Admin secret for issuing invites. If unset, a random one is printed at startup. |
| `PRIMARY_APPROVER` | Username of the primary approver (default `ceo`). |
| `SECONDARY_APPROVERS` | Comma-separated backup approvers (default `coo,cfo,president`). |
| `EXTRA_ALLOWED_ORIGINS` | Extra allowed origins, such as a tunnel URL. |

## Project layout

- `main.py`: server, passkey flows, approvals, proximity handshake, ledger
- `frontend.html`: the single-page interface
- `ai_analyzer.py`: rule checks and the model call
- `evaluate.py`: evaluation script
- `labeled_cases*.json`, `LABELING_RULES.md`: labeled test data and labeling rules
- `test_cases.py`: sample approval used by the analyzer

## Roadmap

- Move receipt writing into the decision handler.
- Derive the step-up code from the approver's phone, not the browser.
- Persist state in a database instead of memory.
