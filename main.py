import os
import time
import base64
import hashlib
import json
import secrets
import sqlite3
from typing import Optional

import pyotp
import webauthn
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# ============================================================
# 1. CONFIG
# ============================================================
RP_NAME = "Tally Code Brewers Auth"

# WebAuthn permanently binds every passkey to the RP ID (domain) that was
# active at REGISTRATION time. A hardcoded "localhost" only ever works from
# the same machine, which is exactly why a phone scanning the QR code could
# never complete the second-device ceremony: "localhost" on a phone means
# the phone itself, not your laptop.
#
# Instead, RP ID and the expected origin are derived from whatever host the
# browser is actually talking to on each request. That means the SAME code
# works unmodified whether you're on http://localhost:8080, a LAN IP, or a
# public HTTPS tunnel (ngrok/cloudflared) -- as long as BOTH devices reach
# the app through that identical hostname for the whole lifetime of a given
# passkey (register once via that hostname, then it's usable from that
# hostname on any device the passkey is synced to, e.g. via iCloud Keychain
# or Google Password Manager).
#
# Set EXTRA_ALLOWED_ORIGINS (comma-separated, e.g.
# "https://abcd1234.ngrok-free.app") if you ever need to allow a second,
# fixed origin on top of whatever the request itself came in on.
def rp_id_for(request: Request) -> str:
    return request.url.hostname or "localhost"

def expected_origin_for(request: Request) -> list[str]:
    host_header = request.headers.get("host", request.url.netloc)
    origins = {f"{request.url.scheme}://{host_header}"}
    for extra in os.environ.get("EXTRA_ALLOWED_ORIGINS", "").split(","):
        extra = extra.strip()
        if extra:
            origins.add(extra)
    return list(origins)

CHALLENGE_TTL_SECONDS = 60           
PROXIMITY_TTL_SECONDS = 90            # window for the second-device QR handshake to be completed
IP_FAILURE_THRESHOLD = 5             
IP_FAILURE_WINDOW_SECONDS = 300      
IP_BAN_DURATION_SECONDS = 600        

ACTION_POLICIES = {
    "STANDARD_LOGIN":  {"tier": "low",      "requires_totp_step_up": False},
    "VAULT_TRANSFER":  {"tier": "critical", "requires_totp_step_up": True},
}
DEFAULT_POLICY = {"tier": "medium", "requires_totp_step_up": False}

def policy_for(action_type: str) -> dict:
    return ACTION_POLICIES.get(action_type, DEFAULT_POLICY)

def require_known_action(action_type: str) -> dict:
    if action_type not in ACTION_POLICIES:
        raise HTTPException(status_code=400, detail="Unknown or unauthorized action type.")
    return ACTION_POLICIES[action_type]

# ============================================================
# 1b. VAULT APPROVAL ROLES (server-authoritative)
# ============================================================
# Who is allowed to approve a vault transaction is decided HERE, on the
# server, and nowhere else. The client used to be trusted to nominate its
# own approvers straight from the request body (ApprovalRequest.approvers /
# .backup_approver), which meant anyone calling the API directly could name
# themselves an approver. Instead:
#
#   PRIMARY_APPROVER    - exactly one person (the CEO). Can approve alone;
#                          no quorum needed.
#   SECONDARY_APPROVERS - exactly the next three in command. Each can act
#                          as a standalone backup, but only once the primary
#                          has had a fair window to respond first.
#   everyone else        - not an approver, full stop. They never even reach
#                          the passkey ceremony for a vault decision.
#
# Configure via env vars in production; these are just sane local defaults.
PRIMARY_APPROVER = os.environ.get("PRIMARY_APPROVER", "ceo").strip()

SECONDARY_APPROVERS = [
    name.strip()
    for name in os.environ.get("SECONDARY_APPROVERS", "coo,cfo,president").split(",")
    if name.strip()
][:3]  # "3 next in command" is a hard cap, not a suggestion

VAULT_ACTION_TYPES = {"VAULT_TRANSFER"}

def approver_role(username: str) -> Optional[str]:
    """Returns 'primary', 'secondary', or None (not an approver at all)."""
    if username == PRIMARY_APPROVER:
        return "primary"
    if username in SECONDARY_APPROVERS:
        return "secondary"
    return None

def require_approver_role(username: str, ip: str):
    if approver_role(username) is None:
        record_ip_failure(ip)
        raise HTTPException(
            status_code=403,
            detail="Only the primary approver or a designated backup approver may act on vault approvals.",
        )

# ============================================================
# 1c. PRIVILEGED-ROLE PROVISIONING (closes username-squatting)
# ============================================================
# Server config decides WHO the approver usernames are, but that alone
# doesn't stop a random caller from being the first to type "ceo" into the
# signup box and permanently bind their own passkey to it. Registration
# for any of the four privileged usernames (PRIMARY_APPROVER + the 3
# SECONDARY_APPROVERS) therefore requires a single-use invite token that
# only someone holding ADMIN_BOOTSTRAP_SECRET can mint. Non-privileged
# usernames are unaffected -- ordinary employees can still self-register
# freely, because they were never going to be trusted with vault approvals
# anyway.
#
# Consuming the token on successful bind also closes a second hole: it
# stops anyone (attacker or otherwise) from re-registering a *new* passkey
# over an already-provisioned privileged account, since a fresh token has
# to be deliberately reissued by the admin to allow that (e.g. rotating in
# a replacement CEO).
ADMIN_BOOTSTRAP_SECRET = os.environ.get("ADMIN_BOOTSTRAP_SECRET") or secrets.token_urlsafe(18)
INVITE_TTL_SECONDS = 24 * 3600

DB_INVITES = {}  # username -> {token, issued_at, expires_at, consumed}

def privileged_usernames() -> set:
    return {PRIMARY_APPROVER} | set(SECONDARY_APPROVERS)

def issue_invite(username: str) -> str:
    token = secrets.token_urlsafe(14)
    DB_INVITES[username] = {
        "token": token,
        "issued_at": time.time(),
        "expires_at": time.time() + INVITE_TTL_SECONDS,
        "consumed": False,
    }
    return token

def validate_invite(username: str, token: Optional[str]):
    """No-op for ordinary usernames. For a privileged username, requires a
    matching, unexpired, not-yet-consumed token minted by an admin."""
    if username not in privileged_usernames():
        return
    invite = DB_INVITES.get(username)
    if not invite or invite["consumed"] or invite["expires_at"] < time.time():
        raise HTTPException(
            status_code=403,
            detail=f"'{username}' is a privileged approver role. Registration requires a fresh admin invite token.",
        )
    if not token or not secrets.compare_digest(token, invite["token"]):
        raise HTTPException(status_code=403, detail="Invalid or missing admin invite token for this role.")

def consume_invite(username: str):
    if username in DB_INVITES:
        DB_INVITES[username]["consumed"] = True

def require_admin(x_admin_secret: Optional[str]):
    if not x_admin_secret or not secrets.compare_digest(x_admin_secret, ADMIN_BOOTSTRAP_SECRET):
        raise HTTPException(status_code=403, detail="Invalid admin secret.")

def init_invites():
    for username in privileged_usernames():
        issue_invite(username)
    print("=" * 64)
    print("VANGUARD ADMIN BOOTSTRAP -- keep this secret out of band")
    print(f"  X-Admin-Secret : {ADMIN_BOOTSTRAP_SECRET}")
    print("  (set ADMIN_BOOTSTRAP_SECRET in the environment to pin this")
    print("   across restarts instead of getting a new one each time)")
    print("-" * 64)
    print("  Initial single-use registration invites for privileged roles:")
    for username, invite in DB_INVITES.items():
        print(f"    {username:<12} -> {invite['token']}")
    print("=" * 64)

# ============================================================
# 2. MODELS
# ============================================================
class UsernamePayload(BaseModel):
    username: str

class RegisterPayload(BaseModel):
    username: str
    invite_token: Optional[str] = None

class UserRequest(BaseModel):
    username: str
    action_type: str = "STANDARD_LOGIN"
    action_meta: dict = {}

class TotpVerifyRequest(BaseModel):
    username: str
    code: str

class RecoveryVerifyRequest(BaseModel):
    username: str
    code: str

class VerificationRequest(BaseModel):
    id: str
    type: str
    rawId: str
    response: dict
    action_context: Optional[dict] = None
    totp_code: Optional[str] = None   

class ApprovalRequest(BaseModel):
    requester: str
    action_type: str
    meta: dict = {}
    # NOTE: approvers / backup approvers / quorum are intentionally NOT
    # accepted here. Who may approve is fixed server-side by role config
    # (see PRIMARY_APPROVER / SECONDARY_APPROVERS above) so a client can
    # never grant itself or anyone else approval rights.

class ApprovalDecision(BaseModel):
    approver: str
    decision: str  
    proof: str

class ProximityStartRequest(BaseModel):
    approver: str
    decision: str = "approve"

class ProximityCompleteRequest(BaseModel):
    approval_proof: str

# ============================================================
# 3. APP INIT & STORAGE
# ============================================================
app = FastAPI(title="Vanguard Authentication Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_USERS = {}            
DB_REG_CHALLENGES = {}   
DB_AUTH_CHALLENGES = {}  
DB_SESSIONS = {}         
DB_RECEIPTS = []         
DB_IP_ACTIVITY = {}      
DB_APPROVALS = {}        
DB_APPROVAL_PROOFS = {}  
DB_PROXIMITY = {}        # token -> dual-custody QR handshake session (second-device biometric proof)
AUDIT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vanguard_audit.db")

def init_audit_store():
    with sqlite3.connect(AUDIT_DB_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS approval_receipts (
                receipt_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, operator TEXT NOT NULL,
                action TEXT NOT NULL, tier TEXT NOT NULL, step_up_used INTEGER NOT NULL,
                meta TEXT NOT NULL, context_hash TEXT, hardware_proof TEXT NOT NULL
            )
        """)

def persist_receipt(receipt: dict):
    with sqlite3.connect(AUDIT_DB_PATH) as connection:
        connection.execute(
            "INSERT INTO approval_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (receipt["receipt_id"], receipt["timestamp"], receipt["operator"], receipt["action"],
             receipt["tier"], int(receipt["step_up_used"]), json.dumps(receipt["meta"]),
             receipt.get("context_hash"), receipt["hardware_proof"]),
        )

init_audit_store()
init_invites()

class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.connections:
            self.connections.remove(websocket)

    async def broadcast(self, event: dict):
        for connection in self.connections[:]:
            try:
                await connection.send_json(event)
            except Exception:
                self.disconnect(connection)

live_updates = ConnectionManager()

def safe_b64url(num_bytes: int) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(num_bytes)).decode("utf-8").rstrip("=")

# ---- IP reputation -----------------------------------------------------
def get_client_ip(request: Request) -> str:
    demo_ip = request.headers.get("x-demo-ip")
    if demo_ip:
        return demo_ip
    return request.client.host if request.client else "unknown"

def ensure_ip_allowed(request: Request):
    ip = get_client_ip(request)
    entry = DB_IP_ACTIVITY.get(ip)
    now = time.time()
    if entry and entry["banned_until"] and entry["banned_until"] > now:
        remaining = int(entry["banned_until"] - now)
        raise HTTPException(
            status_code=403,
            detail=f"IP {ip} is temporarily banned for {remaining}s after repeated failed verifications.",
        )
    return ip

def record_ip_failure(ip: str):
    now = time.time()
    entry = DB_IP_ACTIVITY.setdefault(ip, {"failures": 0, "window_start": now, "banned_until": 0})
    if now - entry["window_start"] > IP_FAILURE_WINDOW_SECONDS:
        entry["failures"] = 0
        entry["window_start"] = now
    entry["failures"] += 1
    if entry["failures"] >= IP_FAILURE_THRESHOLD:
        entry["banned_until"] = now + IP_BAN_DURATION_SECONDS

def record_ip_success(ip: str):
    if ip in DB_IP_ACTIVITY:
        DB_IP_ACTIVITY[ip]["failures"] = 0

# ---- Challenge helpers ---------------------------------------------------
def pop_valid_challenge(store: dict, username: str) -> dict:
    """Returns the full pending-challenge record: {challenge, issued_at, ...}.
    All three callers (register_verify, login_verify, action_verify) rely on
    getting the dict back, not just the raw bytes."""
    entry = store.get(username)
    if not entry:
        raise HTTPException(status_code=400, detail="No pending challenge for this user.")
    del store[username]
    if time.time() - entry["issued_at"] > CHALLENGE_TTL_SECONDS:
        raise HTTPException(status_code=400, detail="Challenge expired. Request a new one.")
    return entry

def context_hash(action_type: str, meta: dict) -> str:
    payload = json.dumps(
        {"action_type": action_type, "meta": meta or {}},
        sort_keys=True, separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def recovery_code_hash(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()

@app.get("/", response_class=HTMLResponse)
def serve_home():
    html_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend.html")
    if not os.path.exists(html_path):
        html_path = "frontend.html"
    try:
        with open(html_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="frontend.html not found next to main.py.")

# ============================================================
# PHASE 1: REGISTRATION
# ============================================================
@app.post("/api/passkey/register-options")
def register_options(payload: RegisterPayload, request: Request):
    ensure_ip_allowed(request)
    username = payload.username
    validate_invite(username, payload.invite_token)
    if username not in DB_USERS:
        DB_USERS[username] = {"id": safe_b64url(16), "credentials": []}

    options = webauthn.generate_registration_options(
        rp_id=rp_id_for(request),
        rp_name=RP_NAME,
        user_name=username,
        user_id=DB_USERS[username]["id"].encode("utf-8"),
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        timeout=CHALLENGE_TTL_SECONDS * 1000,
    )
    # Store the actual raw challenge bytes directly, pinned to the RP ID this
    # registration used so verify-time can't silently drift to a different host.
    DB_REG_CHALLENGES[username] = {"challenge": options.challenge, "issued_at": time.time(), "rp_id": rp_id_for(request)}
    return webauthn.helpers.options_to_json_dict(options)

@app.post("/api/passkey/register-verify/{username}")
def register_verify(username: str, credential: dict, request: Request, invite_token: Optional[str] = None):
    ip = ensure_ip_allowed(request)
    validate_invite(username, invite_token)
    pending = pop_valid_challenge(DB_REG_CHALLENGES, username)
    expected_challenge = pending["challenge"]

    try:
        verified = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=pending["rp_id"],
            expected_origin=expected_origin_for(request),
            require_user_verification=True,
        )
    except Exception as e:
        record_ip_failure(ip)
        raise HTTPException(status_code=400, detail=f"Attestation verification failed: {e}")

    totp_secret = pyotp.random_base32()
    recovery_codes = [secrets.token_urlsafe(6).upper() for _ in range(8)]
    DB_USERS[username]["credential_id"] = webauthn.helpers.bytes_to_base64url(verified.credential_id)
    DB_USERS[username]["public_key"] = verified.credential_public_key
    DB_USERS[username]["sign_count"] = verified.sign_count
    DB_USERS[username]["totp_secret"] = totp_secret
    DB_USERS[username]["recovery_code_hashes"] = {recovery_code_hash(code) for code in recovery_codes}
    consume_invite(username)  # single-use: a second registration attempt now needs a freshly issued token

    record_ip_success(ip)
    return {
        "verified": True,
        "message": "Passkey verified and bound.",
        "totp_secret": totp_secret,
        "totp_uri": pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Vanguard"),
        "recovery_codes": recovery_codes,
    }

# ============================================================
# PHASE 2: STANDARD LOGIN
# ============================================================
@app.post("/api/passkey/login-options")
def login_options(payload: UsernamePayload, request: Request):
    ensure_ip_allowed(request)
    username = payload.username
    user = DB_USERS.get(username)
    if not user or "credential_id" not in user:
        raise HTTPException(status_code=404, detail="User not found or has no bound passkey.")

    options = webauthn.generate_authentication_options(
        rp_id=rp_id_for(request),
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=webauthn.helpers.base64url_to_bytes(user["credential_id"]))
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=CHALLENGE_TTL_SECONDS * 1000,
    )
    DB_AUTH_CHALLENGES[username] = {"challenge": options.challenge, "issued_at": time.time(), "rp_id": rp_id_for(request)}
    return webauthn.helpers.options_to_json_dict(options)

@app.post("/api/passkey/login-verify/{username}")
def login_verify(username: str, credential: dict, request: Request):
    ip = ensure_ip_allowed(request)
    user = DB_USERS.get(username)
    if not user:
        record_ip_failure(ip)
        raise HTTPException(status_code=404, detail="User not found.")

    pending = pop_valid_challenge(DB_AUTH_CHALLENGES, username)
    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=pending["challenge"],
            expected_rp_id=pending["rp_id"],
            expected_origin=expected_origin_for(request),
            credential_public_key=user["public_key"],
            credential_current_sign_count=user["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        record_ip_failure(ip)
        raise HTTPException(status_code=401, detail=f"Signature verification failed: {e}")

    user["sign_count"] = verified.new_sign_count
    record_ip_success(ip)

    token = safe_b64url(32)
    DB_SESSIONS[token] = {"username": username, "expires_at": time.time() + 3600}
    return {"verified": True, "access_token": token}

# ============================================================
# FALLBACKS & ENGINE
# ============================================================
@app.post("/api/totp/verify")
def totp_verify(payload: TotpVerifyRequest, request: Request):
    ip = ensure_ip_allowed(request)
    user = DB_USERS.get(payload.username)
    if not user or "totp_secret" not in user:
        record_ip_failure(ip)
        raise HTTPException(status_code=404, detail="No TOTP fallback provisioned for this user.")

    totp = pyotp.TOTP(user["totp_secret"])
    if not totp.verify(payload.code, valid_window=1):
        record_ip_failure(ip)
        raise HTTPException(status_code=401, detail="Invalid or expired code.")

    record_ip_success(ip)
    token = safe_b64url(32)
    DB_SESSIONS[token] = {"username": payload.username, "expires_at": time.time() + 3600}
    return {"verified": True, "access_token": token, "method": "totp_fallback"}

@app.post("/api/recovery/verify")
def recovery_verify(payload: RecoveryVerifyRequest, request: Request):
    ip = ensure_ip_allowed(request)
    user = DB_USERS.get(payload.username)
    code_hash = recovery_code_hash(payload.code.strip().upper())
    if not user or code_hash not in user.get("recovery_code_hashes", set()):
        record_ip_failure(ip)
        raise HTTPException(status_code=401, detail="Invalid or already-used recovery code.")
    user["recovery_code_hashes"].remove(code_hash)
    record_ip_success(ip)
    token = safe_b64url(32)
    DB_SESSIONS[token] = {"username": payload.username, "expires_at": time.time() + 900}
    return {"verified": True, "access_token": token, "method": "one_time_recovery"}

@app.websocket("/ws/live")
async def live_updates_socket(websocket: WebSocket):
    await live_updates.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        live_updates.disconnect(websocket)

@app.post("/api/approvals")
async def create_approval(payload: ApprovalRequest, request: Request):
    ensure_ip_allowed(request)
    policy = require_known_action(payload.action_type)

    # Approvers are never taken from the client. For vault transactions the
    # roster is always exactly [CEO] with the 3-next-in-command as backup;
    # any other action type that later grows an approval flow gets no
    # approvers at all until it's explicitly wired into the role config.
    if payload.action_type in VAULT_ACTION_TYPES:
        approvers = [PRIMARY_APPROVER]
        backup_approvers = list(SECONDARY_APPROVERS)
    else:
        approvers = []
        backup_approvers = []

    approval_id = safe_b64url(9)
    approval = {
        "approval_id": approval_id,
        "requester": payload.requester,
        "action_type": payload.action_type,
        "meta": payload.meta,
        "tier": policy["tier"],
        "required_quorum": 1,          # the primary alone is sufficient
        "approvers": approvers,        # [CEO]
        "backup_approvers": backup_approvers,  # the 3 next in command
        "approved_by": [],
        "denied_by": [],
        "main_responses": [],  
        "status": "pending",
        "created_at": time.time(),
        "undo_until": None,
        "backup_eligible_after": time.time() + 30,  
    }
    DB_APPROVALS[approval_id] = approval
    await live_updates.broadcast({"event": "approval_requested", "approval": approval})
    return approval

@app.get("/api/approvals")
def get_approvals():
    return sorted(DB_APPROVALS.values(), key=lambda item: item["created_at"], reverse=True)

@app.post("/api/approvals/{approval_id}/decision")
async def decide_approval(approval_id: str, payload: ApprovalDecision, request: Request):
    ip = ensure_ip_allowed(request)
    approval = DB_APPROVALS.get(approval_id)
    if not approval or approval["status"] != "pending":
        raise HTTPException(status_code=404, detail="No pending approval request found.")
    if payload.decision not in {"approve", "deny"}:
        raise HTTPException(status_code=400, detail="Decision must be approve or deny.")
    # Role check first: non-approvers are rejected before we even look at
    # whether they hold a valid passkey proof for this approval.
    require_approver_role(payload.approver, ip)

    proof = DB_APPROVAL_PROOFS.pop(payload.proof, None)
    if (not proof or proof["approval_id"] != approval_id or proof["approver"] != payload.approver
            or proof["expires_at"] < time.time()):
        record_ip_failure(ip)
        raise HTTPException(status_code=403, detail="A fresh passkey verification is required for this decision.")

    is_backup = payload.approver in approval.get("backup_approvers", [])
    if is_backup:
        now = time.time()
        mains_responded = len(approval.get("main_responses", []))
        if mains_responded < len(approval["approvers"]) and now < approval.get("backup_eligible_after", 0):
            record_ip_failure(ip)
            raise HTTPException(status_code=403, detail="A backup approver can only act if the primary approver hasn't responded yet.")

    allowed = approval["approvers"] + approval.get("backup_approvers", [])
    if payload.approver not in allowed:
        record_ip_failure(ip)
        raise HTTPException(status_code=403, detail="This device is not an assigned approver for this request.")

    if payload.approver in approval["approvers"]:
        if payload.approver not in approval.get("main_responses", []):
            approval.setdefault("main_responses", []).append(payload.approver)

    if payload.decision == "deny":
        if payload.approver not in approval.get("denied_by", []):
            approval.setdefault("denied_by", []).append(payload.approver)
        approval["status"] = "denied"
    elif payload.approver not in approval["approved_by"]:
        approval["approved_by"].append(payload.approver)
        if len(approval["approved_by"]) >= approval["required_quorum"]:
            approval["status"] = "approved"
            approval["undo_until"] = time.time() + 5
    record_ip_success(ip)
    await live_updates.broadcast({"event": "approval_updated", "approval": approval})
    return approval

@app.post("/api/approvals/{approval_id}/undo")
async def undo_approval(approval_id: str, request: Request):
    approval = DB_APPROVALS.get(approval_id)
    if not approval or approval["status"] != "approved":
        raise HTTPException(status_code=404, detail="There is no approved request to undo.")
    if not approval["undo_until"] or time.time() > approval["undo_until"]:
        raise HTTPException(status_code=409, detail="The five-second undo window has closed.")
    approval["status"] = "undone"
    await live_updates.broadcast({"event": "approval_updated", "approval": approval})
    return approval


# ============================================================
# PHASE 4: DUAL-CUSTODY PROXIMITY HANDSHAKE (second-device QR flow)
# ============================================================
# An approver decides on Device A (this browser). Instead of signing the
# passkey challenge locally, Device A asks the server to mint a short-lived
# proximity token bound to this exact approval_id + action_hash + decision,
# then renders that token as a QR code. A second, physically separate device
# (Device B, e.g. the approver's phone) scans the code, performs the live
# WebAuthn ceremony itself, and posts the resulting hardware-signed proof
# back here. Device A never sees the signature — it only learns, via the
# live socket, that a second device satisfied the challenge — enforcing a
# real physical boundary between "the device that decided" and "the device
# that proved it's really you".
def proximity_or_404(token: str) -> dict:
    session = DB_PROXIMITY.get(token)
    if not session:
        raise HTTPException(status_code=404, detail="This dual-custody request has expired or was already used.")
    if session["status"] == "awaiting_scan" and time.time() > session["expires_at"]:
        session["status"] = "expired"
    return session

@app.post("/api/approvals/{approval_id}/proximity-start")
async def start_proximity(approval_id: str, payload: ProximityStartRequest, request: Request):
    ip = ensure_ip_allowed(request)
    approval = DB_APPROVALS.get(approval_id)
    if not approval or approval["status"] != "pending":
        raise HTTPException(status_code=404, detail="No pending approval request found.")
    if payload.decision not in {"approve", "deny"}:
        raise HTTPException(status_code=400, detail="Decision must be approve or deny.")

    require_approver_role(payload.approver, ip)
    allowed = approval["approvers"] + approval.get("backup_approvers", [])
    if payload.approver not in allowed:
        record_ip_failure(ip)
        raise HTTPException(status_code=403, detail="This device is not an assigned approver for this request.")

    # Bind the handshake to the exact action being decided so a scanned code
    # can never be replayed against a different transfer or approval.
    meta = {**approval.get("meta", {}), "approval_id": approval_id}
    action_hash = context_hash(approval["action_type"], meta)
    token = safe_b64url(12)
    session = {
        "token": token,
        "approval_id": approval_id,
        "approver": payload.approver,
        "decision": payload.decision,
        "action_type": approval["action_type"],
        "meta": meta,
        "action_hash": action_hash,
        "status": "awaiting_scan",
        "created_at": time.time(),
        "expires_at": time.time() + PROXIMITY_TTL_SECONDS,
        "approval_proof": None,
    }
    DB_PROXIMITY[token] = session
    record_ip_success(ip)
    await live_updates.broadcast({"event": "proximity_started", "token": token, "approval_id": approval_id})
    return {
        "token": token,
        "action_hash": action_hash,
        "expires_at": session["expires_at"],
        "handoff_url": f"{str(request.base_url).rstrip('/')}/?proximity={token}",
    }

@app.get("/api/proximity/{token}")
def get_proximity(token: str):
    return proximity_or_404(token)

@app.post("/api/proximity/{token}/complete")
async def complete_proximity(token: str, payload: ProximityCompleteRequest, request: Request):
    ip = ensure_ip_allowed(request)
    session = proximity_or_404(token)
    if session["status"] != "awaiting_scan":
        raise HTTPException(status_code=409, detail="This dual-custody request is no longer awaiting a scan.")

    # The proof itself was only issued by /api/passkey/action-verify after a
    # genuine hardware signature, so this just has to confirm Device B proved
    # the *same* approver against the *same* approval before we trust it.
    proof = DB_APPROVAL_PROOFS.get(payload.approval_proof)
    if (not proof or proof["approval_id"] != session["approval_id"]
            or proof["approver"] != session["approver"] or proof["expires_at"] < time.time()):
        record_ip_failure(ip)
        raise HTTPException(status_code=403, detail="That passkey proof doesn't match this dual-custody request.")

    session["status"] = "verified"
    session["approval_proof"] = payload.approval_proof
    record_ip_success(ip)
    await live_updates.broadcast({
        "event": "proximity_completed",
        "token": token,
        "approval_id": session["approval_id"],
    })
    return session

@app.post("/api/security/this-wasnt-me/{username}")
async def report_compromise(username: str, request: Request):
    ensure_ip_allowed(request)
    revoked = 0
    for token, session in list(DB_SESSIONS.items()):
        if session["username"] == username:
            del DB_SESSIONS[token]
            revoked += 1
    DB_AUTH_CHALLENGES.pop(username, None)
    await live_updates.broadcast({"event": "identity_locked", "username": username})
    return {"status": "locked", "revoked_sessions": revoked}

# ============================================================
# PHASE 3: ACTION ENGINE (Fixes encoding mismatches)
# ============================================================
@app.post("/api/passkey/action-options")
def action_options(req: UserRequest, request: Request):
    ensure_ip_allowed(request)
    require_known_action(req.action_type)
    user = DB_USERS.get(req.username)
    if not user or "credential_id" not in user:
        raise HTTPException(status_code=404, detail="User not found or has no bound passkey.")

    action_hash = context_hash(req.action_type, req.action_meta)
    
    # Generate the exact byte array challenge structure
    challenge_bytes = hashlib.sha256(
        secrets.token_bytes(32) + action_hash.encode("ascii")
    ).digest()
    
    options = webauthn.generate_authentication_options(
        rp_id=rp_id_for(request),
        challenge=challenge_bytes,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=webauthn.helpers.base64url_to_bytes(user["credential_id"]))
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=CHALLENGE_TTL_SECONDS * 1000,
    )
    
    # Store the actual raw challenge bytes directly, pinned to the RP ID this
    # device is talking to (matters most here: this is the endpoint the
    # SECOND device calls during the dual-custody QR handshake).
    DB_AUTH_CHALLENGES[req.username] = {
        "challenge": options.challenge,
        "issued_at": time.time(),
        "action_hash": action_hash,
        "rp_id": rp_id_for(request),
    }
    return webauthn.helpers.options_to_json_dict(options)

@app.post("/api/passkey/action-verify/{username}")
def action_verify(username: str, req: VerificationRequest, request: Request):
    ip = ensure_ip_allowed(request)
    user = DB_USERS.get(username)
    if not user:
        record_ip_failure(ip)
        raise HTTPException(status_code=404, detail="User not found.")

    claimed_action_type = (req.action_context or {}).get("action_type", "STANDARD_LOGIN")
    meta = (req.action_context or {}).get("meta", {})
    approval_id = meta.get("approval_id")

    approval = DB_APPROVALS.get(approval_id) if approval_id else None
    if approval_id and not approval:
        record_ip_failure(ip)
        raise HTTPException(status_code=404, detail="The referenced approval request does not exist.")
    action_type = approval["action_type"] if approval else claimed_action_type
    policy = require_known_action(action_type)

    pending = pop_valid_challenge(DB_AUTH_CHALLENGES, username)
    expected_challenge = pending
    
    if pending.get("action_hash") != context_hash(claimed_action_type, meta):
        record_ip_failure(ip)
        raise HTTPException(status_code=400, detail="Action context changed after approval was requested.")
        
    credential = {"id": req.id, "type": req.type, "rawId": req.rawId, "response": req.response}
    try:
        verified = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge["challenge"],
            expected_rp_id=pending.get("rp_id", rp_id_for(request)),
            expected_origin=expected_origin_for(request),
            credential_public_key=user["public_key"],
            credential_current_sign_count=user["sign_count"],
            require_user_verification=True,
        )
    except Exception as e:
        record_ip_failure(ip)
        raise HTTPException(status_code=401, detail=f"Signature verification failed: {e}")
    user["sign_count"] = verified.new_sign_count

    if policy["requires_totp_step_up"]:
        if not req.totp_code:
            record_ip_failure(ip)
            raise HTTPException(status_code=403, detail="This action requires a TOTP step-up code.")
        totp = pyotp.TOTP(user.get("totp_secret", ""))
        if not totp.verify(req.totp_code, valid_window=1):
            record_ip_failure(ip)
            raise HTTPException(status_code=401, detail="Invalid TOTP step-up code.")

    record_ip_success(ip)
    signature_b64 = req.response.get("signature", "")
    receipt = {
        "receipt_id": base64.b64encode(os.urandom(16)).decode("utf-8").replace("=", "").upper()[:8],
        "timestamp": time.time(),
        "operator": username,
        "action": action_type,
        "tier": policy["tier"],
        "step_up_used": policy["requires_totp_step_up"],
        "meta": meta,
        "context_hash": pending.get("action_hash"),
        "hardware_proof": signature_b64[:24] + "..." if signature_b64 else "N/A",
    }
    DB_RECEIPTS.append(receipt)
    persist_receipt(receipt)
    
    approval_proof = None
    if approval_id:
        if approval["status"] != "pending":
            raise HTTPException(status_code=404, detail="The live approval request is no longer pending.")
        approval_proof = safe_b64url(24)
        DB_APPROVAL_PROOFS[approval_proof] = {
            "approval_id": approval_id, "approver": username, "expires_at": time.time() + 60,
        }
    return {"status": "verified", "receipt": receipt, "approval_proof": approval_proof}

@app.get("/api/ledger")
def get_ledger():
    with sqlite3.connect(AUDIT_DB_PATH) as connection:
        rows = connection.execute(
            "SELECT receipt_id, timestamp, operator, action, tier, step_up_used, meta, context_hash, hardware_proof "
            "FROM approval_receipts ORDER BY timestamp ASC"
        ).fetchall()
    return [
        {"receipt_id": row[0], "timestamp": row[1], "operator": row[2], "action": row[3],
         "tier": row[4], "step_up_used": bool(row[5]), "meta": json.loads(row[6]),
         "context_hash": row[7], "hardware_proof": row[8]}
        for row in rows
    ]

@app.get("/api/policy/{action_type}")
def get_policy(action_type: str):
    return require_known_action(action_type)

@app.get("/api/approvers")
def get_approvers():
    """Read-only view of who's allowed to approve vault transactions. This
    reflects server config; it is never something a client can change."""
    return {"primary_approver": PRIMARY_APPROVER, "secondary_approvers": SECONDARY_APPROVERS}

@app.get("/api/admin/invites")
def list_invites(x_admin_secret: Optional[str] = Header(None)):
    """Admin-only: shows whether each privileged role is still unclaimed,
    and its current invite token if so. Never exposes anything for
    non-privileged usernames -- there's nothing to gate there."""
    require_admin(x_admin_secret)
    now = time.time()
    return [
        {
            "username": username,
            "claimed": "credential_id" in DB_USERS.get(username, {}),
            "invite_token": None if invite["consumed"] else invite["token"],
            "expires_in_seconds": max(0, int(invite["expires_at"] - now)),
            "consumed": invite["consumed"],
        }
        for username, invite in DB_INVITES.items()
    ]

@app.post("/api/admin/invites/{username}/reissue")
def reissue_invite(username: str, x_admin_secret: Optional[str] = Header(None)):
    """Admin-only: mint a fresh single-use invite for a privileged role --
    e.g. onboarding a replacement CEO, or re-provisioning a backup approver
    whose device was lost. Deliberately does NOT revoke an existing bound
    passkey; that's a separate, more sensitive action left out of scope
    here (would need its own audited flow)."""
    require_admin(x_admin_secret)
    if username not in privileged_usernames():
        raise HTTPException(status_code=400, detail="Only the four privileged approver roles use invite tokens.")
    token = issue_invite(username)
    print(f"[ADMIN] Reissued invite for '{username}': {token}")
    return {"username": username, "invite_token": token, "expires_in_seconds": INVITE_TTL_SECONDS}

@app.get("/api/approver-role/{username}")
def get_approver_role(username: str):
    """Read-only lookup so the UI can show someone their own standing
    (primary / backup / not an approver) before they ever try to act.
    Purely informational -- it grants nothing. The actual gate is still
    require_approver_role() at decision time, which never trusts the client."""
    role = approver_role(username)
    return {
        "username": username,
        "role": role or "none",
        "can_approve_vault": role is not None,
    }

@app.get("/api/security/ip-status")
def ip_status(request: Request):
    ip = get_client_ip(request)
    entry = DB_IP_ACTIVITY.get(ip, {"failures": 0, "banned_until": 0})
    now = time.time()
    return {
        "ip": ip,
        "failures": entry["failures"],
        "banned": entry["banned_until"] > now,
        "banned_seconds_remaining": max(0, int(entry["banned_until"] - now)),
    }