from fastapi import FastAPI, HTTPException, Request, Depends, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, hashlib, secrets, os, time, hmac, base64, json
from datetime import datetime, timedelta, date
import jwt
try:
    from openai import OpenAI as OpenAIClient
except ImportError:
    OpenAIClient = None

from database import get_db, init_db

# ── photo upload setup ────────────────────────────────────────
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
MAX_SIZE = 10 * 1024 * 1024  # 10MB


SECRET_KEY = os.environ.get("SECRET_KEY") or (_ for _ in ()).throw(ValueError("SECRET_KEY env var not set"))
ALGORITHM  = "HS256"

# ── ブルートフォース対策 ──────────────────────────────────────────
import time as _time
from collections import defaultdict as _defaultdict
_login_attempts: dict = _defaultdict(list)
_LIMIT_COUNT = 10
_LIMIT_WINDOW = 600

def _get_real_ip(request) -> str:
    return (request.headers.get("X-Real-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or getattr(request.client, "host", "unknown"))

def _check_rate_limit(ip: str):
    now = _time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _LIMIT_WINDOW]
    if len(_login_attempts[ip]) >= _LIMIT_COUNT:
        raise HTTPException(429, "Too many login attempts. Try again in 10 minutes.")
    _login_attempts[ip].append(now)

BASE_PATH  = "/keikaku"
WELFARE_SSO_SECRET = os.environ.get("WELFARE_SSO_SECRET") or (_ for _ in ()).throw(ValueError("WELFARE_SSO_SECRET env var not set"))

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, root_path=BASE_PATH)

# ── nginx経由以外の直接ポートアクセス遮断 ─────────────────────────
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as _StarResponse

class _LocalhostOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        client_host = getattr(request.client, "host", "")
        if client_host in ("127.0.0.1", "::1", "localhost"):
            return await call_next(request)
        if request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For"):
            return await call_next(request)
        return _StarResponse("Forbidden", status_code=403)

app.add_middleware(_LocalhostOnlyMiddleware)

# ── セキュリティレスポンスヘッダー ────────────────────────────────
class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Server"] = ""
        return response

app.add_middleware(_SecurityHeadersMiddleware)


app.add_middleware(CORSMiddleware,
    allow_origins=[
        "https://gaiaarts.org", "https://www.gaiaarts.org",
        "https://meet.gaiaarts.org", "https://life-energy-coaching.net",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"])
init_db()
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── パスワードハッシュ (bcrypt + SHA256後方互換) ──────────────────
import hashlib as _hashlib
try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False

def hash_pw(pw: str, salt: str = "") -> str:
    if _BCRYPT_AVAILABLE:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(rounds=12)).decode()
    return _hashlib.sha256((pw + salt).encode()).hexdigest()

def verify_pw(pw: str, stored_hash: str, salt: str = "") -> bool:
    if _BCRYPT_AVAILABLE and (stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$")):
        try:
            return _bcrypt.checkpw(pw.encode(), stored_hash.encode())
        except Exception:
            return False
    return _hashlib.sha256((pw + salt).encode()).hexdigest() == stored_hash


def make_token(oid, username):
    return jwt.encode({"sub":str(oid),"username":username,"exp":datetime.utcnow()+timedelta(days=30)}, SECRET_KEY, algorithm=ALGORITHM)

def current_office(request: Request):
    auth = request.headers.get("Authorization","")
    if not auth.startswith("Bearer "): raise HTTPException(401)
    try: return int(jwt.decode(auth[7:], SECRET_KEY, algorithms=[ALGORITHM])["sub"])
    except: raise HTTPException(401)

def current_office_query(request: Request, token: Optional[str] = None):
    """Auth that accepts token as query param (for window.open/href downloads)"""
    tok = token
    if not tok:
        auth = request.headers.get("authorization", "")
        tok = auth.replace("Bearer ", "") if auth else None
    if not tok:
        raise HTTPException(status_code=401, detail="Unauthorized")
    try:
        payload = jwt.decode(tok, SECRET_KEY, algorithms=["HS256"])
        return int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=401, detail="Unauthorized")


def check_active(oid, db):
    row = db.execute("SELECT subscription_status,trial_end FROM offices WHERE id=?", (oid,)).fetchone()
    if not row: raise HTTPException(403)
    if row["subscription_status"]=="active": return
    if row["subscription_status"]=="trial":
        if row["trial_end"] and datetime.now()>datetime.fromisoformat(row["trial_end"]): raise HTTPException(403,"trial_expired")
        return
    raise HTTPException(403)

class RegisterIn(BaseModel):
    username: str
    office_name: str
    email: str
    password: str

class LoginIn(BaseModel):
    username: str
    password: str

class CounselorIn(BaseModel):
    name: str
    kana: Optional[str] = ""
    cert_acquired: Optional[str] = ""
    cert_next_renewal: Optional[str] = ""
    is_chief: Optional[int] = 0
    is_active: Optional[int] = 1

class ClientIn(BaseModel):
    counselor_id: Optional[int] = None
    name: str
    kana: Optional[str] = ""
    gender: Optional[str] = ""
    birthdate: Optional[str] = ""
    disability_type: Optional[str] = ""
    disability_level: Optional[str] = ""
    jukyusha_no: Optional[str] = ""
    jukyusha_valid_to: Optional[str] = ""
    address: Optional[str] = ""
    phone: Optional[str] = ""
    family_name: Optional[str] = ""
    family_phone: Optional[str] = ""
    main_service: Optional[str] = ""
    contract_date: Optional[str] = ""
    monitoring_frequency: Optional[str] = "6months"
    next_monitoring_date: Optional[str] = ""
    last_monitoring_date: Optional[str] = ""
    notes: Optional[str] = ""
    is_active: Optional[int] = 1

class AssessmentIn(BaseModel):
    client_id: int
    assess_date: str
    living_situation: Optional[str] = ""
    daily_life: Optional[str] = ""
    family_support: Optional[str] = ""
    social_resources: Optional[str] = ""
    strengths: Optional[str] = ""
    challenges: Optional[str] = ""
    hopes: Optional[str] = ""
    notes: Optional[str] = ""

class ServicePlanIn(BaseModel):
    client_id: int
    plan_type: Optional[str] = "draft"
    created_date: str
    approved_date: Optional[str] = ""
    long_term_goal: Optional[str] = ""
    short_term_goal: Optional[str] = ""
    support_policy: Optional[str] = ""
    weekly_schedule: Optional[str] = ""
    weekly_grid_json: Optional[str] = "{}"
    services: Optional[str] = "[]"
    notes: Optional[str] = ""
    version: Optional[int] = 1

class MonitoringReportIn(BaseModel):
    client_id: int
    monitor_date: str
    visit_date: Optional[str] = ""
    counselor_id: Optional[int] = None
    goal_achievement: Optional[str] = "partial"
    satisfaction: Optional[str] = "normal"
    service_status: Optional[str] = ""
    issues: Optional[str] = ""
    plan_change: Optional[str] = "no_change"
    next_monitoring: Optional[str] = ""
    notes: Optional[str] = ""
    client_wishes: Optional[str] = ""
    submitted_to_city: Optional[int] = 0

class CaseConferenceIn(BaseModel):
    client_id: int
    conference_date: str
    location: Optional[str] = ""
    attendees: Optional[str] = ""
    agenda: Optional[str] = ""
    minutes: Optional[str] = ""

class ConsultationRecordIn(BaseModel):
    client_id: Optional[int] = None
    record_date: str
    counselor_id: Optional[int] = None
    method: Optional[str] = "visit"
    contact_type: Optional[str] = "client"
    content: str
    response: Optional[str] = ""
    followup: Optional[str] = ""

class HandoverIn(BaseModel):
    staff_name: str
    content: str
    priority: Optional[str] = "normal"

@app.post("/api/register")
def register(body: RegisterIn, request: Request):
    _check_rate_limit(_get_real_ip(request))
    if len(body.password) < 8 or len(body.password) > 128:
        raise HTTPException(400, 'パスワードは8〜128文字で設定してください')
    if len(body.username) < 1 or len(body.username) > 100:
        raise HTTPException(400, 'ユーザー名は1〜100文字で設定してください')
    db = get_db()
    try:
        salt = secrets.token_hex(16)
        ph = hash_pw(body.password, salt)
        trial_end = (datetime.now() + timedelta(days=30)).isoformat()
        db.execute("INSERT INTO offices (username,office_name,email,pw_hash,pw_salt,trial_end) VALUES (?,?,?,?,?,?)",
            (body.username, body.office_name, body.email, ph, salt, trial_end))
        db.commit()
        row = db.execute("SELECT id FROM offices WHERE username=?", (body.username,)).fetchone()
        return {"token": make_token(row["id"], body.username), "office_name": body.office_name}
    except Exception as e:
        raise HTTPException(400, str(e))
    finally:
        db.close()

@app.post("/api/login")
def login(body: LoginIn, request: Request):

    _check_rate_limit(_get_real_ip(request))
    db = get_db()
    try:
        row = db.execute("SELECT * FROM offices WHERE username=?", (body.username,)).fetchone()
        if not row: raise HTTPException(401, "invalid credentials")
        if not verify_pw(body.password, row["pw_hash"], row["pw_salt"]): raise HTTPException(401, "invalid credentials")
        return {"token": make_token(row["id"], body.username), "office_name": row["office_name"]}
    finally:
        db.close()

@app.get("/api/me")
def me(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        row = db.execute("SELECT id,username,office_name,email,plan,subscription_status,trial_end,jigyosho_no,pref_no,tanka_unit FROM offices WHERE id=?", (oid,)).fetchone()
        if not row: raise HTTPException(404)
        return dict(row)
    finally:
        db.close()

@app.get("/api/dashboard")
def dashboard(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        today = date.today()
        today_str = today.isoformat()
        this_month_end = (today.replace(day=1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        next_month_start = this_month_end + timedelta(days=1)
        next_month_end = (next_month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        counselors = db.execute("SELECT id,name FROM counselors WHERE office_id=? AND is_active=1", (oid,)).fetchall()
        counselor_counts = []
        for c in counselors:
            cnt = db.execute("SELECT COUNT(*) as cnt FROM clients WHERE office_id=? AND counselor_id=? AND is_active=1", (oid, c["id"])).fetchone()["cnt"]
            counselor_counts.append({"counselor_id": c["id"], "counselor_name": c["name"], "count": cnt, "over_limit": cnt > 39})
        overdue = db.execute("SELECT COUNT(*) as cnt FROM clients WHERE office_id=? AND is_active=1 AND next_monitoring_date!='' AND next_monitoring_date<?", (oid, today_str)).fetchone()["cnt"]
        this_month = db.execute("SELECT COUNT(*) as cnt FROM clients WHERE office_id=? AND is_active=1 AND next_monitoring_date>=? AND next_monitoring_date<=?", (oid, today_str, this_month_end.isoformat())).fetchone()["cnt"]
        next_month_cnt = db.execute("SELECT COUNT(*) as cnt FROM clients WHERE office_id=? AND is_active=1 AND next_monitoring_date>=? AND next_monitoring_date<=?", (oid, next_month_start.isoformat(), next_month_end.isoformat())).fetchone()["cnt"]
        jukyusha_expired = db.execute("SELECT COUNT(*) as cnt FROM clients WHERE office_id=? AND is_active=1 AND jukyusha_valid_to!='' AND jukyusha_valid_to<?", (oid, today_str)).fetchone()["cnt"]
        return {"counselor_counts": counselor_counts, "monitoring_overdue_count": overdue, "this_month_monitoring": this_month, "next_month_monitoring": next_month_cnt, "jukyusha_expired_count": jukyusha_expired}
    finally:
        db.close()

@app.get("/api/counselors")
def list_counselors(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM counselors WHERE office_id=? ORDER BY is_chief DESC, name", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/counselors")
def create_counselor(body: CounselorIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("INSERT INTO counselors (office_id,name,kana,cert_acquired,cert_next_renewal,is_chief,is_active) VALUES (?,?,?,?,?,?,?)",
            (oid, body.name, body.kana, body.cert_acquired, body.cert_next_renewal, body.is_chief, body.is_active))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.put("/api/counselors/{cid}")
def update_counselor(cid: int, body: CounselorIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("UPDATE counselors SET name=?,kana=?,cert_acquired=?,cert_next_renewal=?,is_chief=?,is_active=? WHERE id=? AND office_id=?",
            (body.name, body.kana, body.cert_acquired, body.cert_next_renewal, body.is_chief, body.is_active, cid, oid))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.delete("/api/counselors/{cid}")
def delete_counselor(cid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("DELETE FROM counselors WHERE id=? AND office_id=?", (cid, oid))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.get("/api/clients")
def list_clients(request: Request, counselor_id: Optional[int] = None, search: Optional[str] = None):
    oid = current_office(request)
    db = get_db()
    try:
        q = "SELECT c.*, co.name as counselor_name FROM clients c LEFT JOIN counselors co ON c.counselor_id=co.id WHERE c.office_id=?"
        params = [oid]
        if counselor_id:
            q += " AND c.counselor_id=?"
            params.append(counselor_id)
        if search:
            q += " AND (c.name LIKE ? OR c.kana LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        q += " ORDER BY c.kana, c.name"
        rows = db.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/clients")
def create_client(body: ClientIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("""INSERT INTO clients (office_id,counselor_id,name,kana,gender,birthdate,disability_type,disability_level,
            jukyusha_no,jukyusha_valid_to,address,phone,family_name,family_phone,main_service,contract_date,
            monitoring_frequency,next_monitoring_date,last_monitoring_date,notes,is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (oid, body.counselor_id, body.name, body.kana, body.gender, body.birthdate,
             body.disability_type, body.disability_level, body.jukyusha_no, body.jukyusha_valid_to,
             body.address, body.phone, body.family_name, body.family_phone, body.main_service,
             body.contract_date, body.monitoring_frequency, body.next_monitoring_date,
             body.last_monitoring_date, body.notes, body.is_active))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.get("/api/clients/{client_id}")
def get_client(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        row = db.execute("SELECT c.*, co.name as counselor_name FROM clients c LEFT JOIN counselors co ON c.counselor_id=co.id WHERE c.id=? AND c.office_id=?", (client_id, oid)).fetchone()
        if not row: raise HTTPException(404)
        return dict(row)
    finally:
        db.close()

@app.put("/api/clients/{client_id}")
def update_client(client_id: int, body: ClientIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("""UPDATE clients SET counselor_id=?,name=?,kana=?,gender=?,birthdate=?,disability_type=?,disability_level=?,
            jukyusha_no=?,jukyusha_valid_to=?,address=?,phone=?,family_name=?,family_phone=?,main_service=?,
            contract_date=?,monitoring_frequency=?,next_monitoring_date=?,last_monitoring_date=?,notes=?,is_active=?
            WHERE id=? AND office_id=?""",
            (body.counselor_id, body.name, body.kana, body.gender, body.birthdate,
             body.disability_type, body.disability_level, body.jukyusha_no, body.jukyusha_valid_to,
             body.address, body.phone, body.family_name, body.family_phone, body.main_service,
             body.contract_date, body.monitoring_frequency, body.next_monitoring_date,
             body.last_monitoring_date, body.notes, body.is_active, client_id, oid))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.delete("/api/clients/{client_id}")
def delete_client(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("DELETE FROM clients WHERE id=? AND office_id=?", (client_id, oid))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.get("/api/monitoring-alerts")
def monitoring_alerts(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        today = date.today()
        today_str = today.isoformat()
        tme = (today.replace(day=1) + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        nms = tme + timedelta(days=1)
        nme = (nms + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        t3m = (today + timedelta(days=90)).isoformat()
        def fa(wc, p):
            rows = db.execute(f"""SELECT c.id, c.name as client_name, co.name as counselor_name, c.next_monitoring_date
                FROM clients c LEFT JOIN counselors co ON c.counselor_id=co.id
                WHERE c.office_id=? AND c.is_active=1 AND c.next_monitoring_date!='' {wc}
                ORDER BY c.next_monitoring_date""", [oid]+p).fetchall()
            res=[]
            for r in rows:
                d=date.fromisoformat(r["next_monitoring_date"]) if r["next_monitoring_date"] else None
                du=(d-today).days if d else None
                res.append({**dict(r),"days_until":du})
            return res
        return {"overdue":fa("AND c.next_monitoring_date<?",[today_str]),"this_month":fa("AND c.next_monitoring_date>=? AND c.next_monitoring_date<=?",[today_str,tme.isoformat()]),"next_month":fa("AND c.next_monitoring_date>=? AND c.next_monitoring_date<=?",[nms.isoformat(),nme.isoformat()]),"upcoming":fa("AND c.next_monitoring_date>? AND c.next_monitoring_date<=?",[nme.isoformat(),t3m])}
    finally:
        db.close()

@app.get("/api/case-counts")
def case_counts(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("""SELECT co.id, co.name, COUNT(c.id) as count
            FROM counselors co LEFT JOIN clients c ON co.id=c.counselor_id AND c.is_active=1
            WHERE co.office_id=? AND co.is_active=1
            GROUP BY co.id, co.name ORDER BY co.name""", (oid,)).fetchall()
        return [{"counselor_id":r["id"],"counselor_name":r["name"],"count":r["count"],"over_limit":r["count"]>39} for r in rows]
    finally:
        db.close()

@app.get("/api/assessments")
def list_assessments(request: Request, client_id: Optional[int] = None):
    oid = current_office(request)
    db = get_db()
    try:
        q = "SELECT a.*, c.name as client_name FROM assessments a JOIN clients c ON a.client_id=c.id WHERE a.office_id=?"
        params = [oid]
        if client_id: q += " AND a.client_id=?"; params.append(client_id)
        q += " ORDER BY a.assess_date DESC"
        rows = db.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/assessments")
def create_assessment(body: AssessmentIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("""INSERT INTO assessments (office_id,client_id,assess_date,living_situation,daily_life,family_support,
            social_resources,strengths,challenges,hopes,notes) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (oid,body.client_id,body.assess_date,body.living_situation,body.daily_life,
             body.family_support,body.social_resources,body.strengths,body.challenges,body.hopes,body.notes))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.get("/api/assessments/{aid}")
def get_assessment(aid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        row = db.execute("SELECT * FROM assessments WHERE id=? AND office_id=?", (aid, oid)).fetchone()
        if not row: raise HTTPException(404)
        return dict(row)
    finally:
        db.close()

@app.get("/api/service-plans")
def list_service_plans(request: Request, client_id: Optional[int] = None):
    oid = current_office(request)
    db = get_db()
    try:
        q = "SELECT sp.*, c.name as client_name FROM service_plans sp JOIN clients c ON sp.client_id=c.id WHERE sp.office_id=?"
        params = [oid]
        if client_id: q += " AND sp.client_id=?"; params.append(client_id)
        q += " ORDER BY sp.created_date DESC"
        rows = db.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/service-plans")
def create_service_plan(body: ServicePlanIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("""INSERT INTO service_plans (office_id,client_id,plan_type,created_date,approved_date,long_term_goal,
            short_term_goal,support_policy,weekly_schedule,weekly_grid_json,services,notes,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (oid,body.client_id,body.plan_type,body.created_date,body.approved_date,
             body.long_term_goal,body.short_term_goal,body.support_policy,body.weekly_schedule,
             body.weekly_grid_json or '{}',body.services,body.notes,body.version))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.get("/api/service-plans/{pid}")
def get_service_plan(pid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        row = db.execute("SELECT * FROM service_plans WHERE id=? AND office_id=?", (pid, oid)).fetchone()
        if not row: raise HTTPException(404)
        return dict(row)
    finally:
        db.close()

@app.put("/api/service-plans/{pid}")
def update_service_plan(pid: int, body: ServicePlanIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("""UPDATE service_plans SET plan_type=?,created_date=?,approved_date=?,long_term_goal=?,short_term_goal=?,
            support_policy=?,weekly_schedule=?,weekly_grid_json=?,services=?,notes=?,version=? WHERE id=? AND office_id=?""",
            (body.plan_type,body.created_date,body.approved_date,body.long_term_goal,body.short_term_goal,
             body.support_policy,body.weekly_schedule,body.weekly_grid_json or '{}',
             body.services,body.notes,body.version,pid,oid))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

# ===== 週間計画テンプレート =====
class WeeklyTemplateIn(BaseModel):
    name: str
    grid_json: Optional[str] = "{}"

@app.get("/api/weekly-templates")
def list_weekly_templates(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM weekly_templates WHERE office_id=? ORDER BY created_at DESC", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/weekly-templates")
def create_weekly_template(body: WeeklyTemplateIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("INSERT INTO weekly_templates (office_id,name,grid_json) VALUES (?,?,?)",
                   (oid, body.name, body.grid_json or '{}'))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.delete("/api/weekly-templates/{tid}")
def delete_weekly_template(tid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("DELETE FROM weekly_templates WHERE id=? AND office_id=?", (tid, oid))
        db.commit()
        return {"ok": True}
    finally:
        db.close()

@app.get("/api/monitoring-reports")
def list_monitoring_reports(request: Request, client_id: Optional[int] = None):
    oid = current_office(request)
    db = get_db()
    try:
        q = "SELECT mr.*, c.name as client_name, co.name as counselor_name FROM monitoring_reports mr JOIN clients c ON mr.client_id=c.id LEFT JOIN counselors co ON mr.counselor_id=co.id WHERE mr.office_id=?"
        params = [oid]
        if client_id: q += " AND mr.client_id=?"; params.append(client_id)
        q += " ORDER BY mr.monitor_date DESC"
        rows = db.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/monitoring-reports")
def create_monitoring_report(body: MonitoringReportIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("""INSERT INTO monitoring_reports (office_id,client_id,monitor_date,visit_date,counselor_id,goal_achievement,
            satisfaction,service_status,issues,plan_change,next_monitoring,notes,submitted_to_city,client_wishes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (oid,body.client_id,body.monitor_date,body.visit_date,body.counselor_id,
             body.goal_achievement,body.satisfaction,body.service_status,body.issues,
             body.plan_change,body.next_monitoring,body.notes,body.submitted_to_city,body.client_wishes or ''))
        if body.next_monitoring:
            db.execute("UPDATE clients SET last_monitoring_date=?, next_monitoring_date=? WHERE id=? AND office_id=?",
                (body.monitor_date,body.next_monitoring,body.client_id,oid))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.put("/api/monitoring-reports/{rid}")
def update_monitoring_report(rid: int, body: MonitoringReportIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("""UPDATE monitoring_reports SET monitor_date=?,visit_date=?,counselor_id=?,goal_achievement=?,satisfaction=?,
            service_status=?,issues=?,plan_change=?,next_monitoring=?,notes=?,submitted_to_city=?,client_wishes=?
            WHERE id=? AND office_id=?""",
            (body.monitor_date,body.visit_date,body.counselor_id,body.goal_achievement,body.satisfaction,
             body.service_status,body.issues,body.plan_change,body.next_monitoring,body.notes,
             body.submitted_to_city,body.client_wishes or '',rid,oid))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.get("/api/case-conferences")
def list_case_conferences(request: Request, client_id: Optional[int] = None):
    oid = current_office(request)
    db = get_db()
    try:
        q = "SELECT cc.*, c.name as client_name FROM case_conferences cc JOIN clients c ON cc.client_id=c.id WHERE cc.office_id=?"
        params = [oid]
        if client_id: q += " AND cc.client_id=?"; params.append(client_id)
        q += " ORDER BY cc.conference_date DESC"
        rows = db.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/case-conferences")
def create_case_conference(body: CaseConferenceIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("INSERT INTO case_conferences (office_id,client_id,conference_date,location,attendees,agenda,minutes) VALUES (?,?,?,?,?,?,?)",
            (oid,body.client_id,body.conference_date,body.location,body.attendees,body.agenda,body.minutes))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.get("/api/consultation-records")
def list_consultation_records(request: Request, client_id: Optional[int] = None, record_date: Optional[str] = None):
    oid = current_office(request)
    db = get_db()
    try:
        q = "SELECT cr.*, c.name as client_name, co.name as counselor_name FROM consultation_records cr LEFT JOIN clients c ON cr.client_id=c.id LEFT JOIN counselors co ON cr.counselor_id=co.id WHERE cr.office_id=?"
        params = [oid]
        if client_id: q += " AND cr.client_id=?"; params.append(client_id)
        if record_date: q += " AND cr.record_date=?"; params.append(record_date)
        q += " ORDER BY cr.record_date DESC, cr.created_at DESC"
        rows = db.execute(q, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/consultation-records")
def create_consultation_record(body: ConsultationRecordIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        check_active(oid, db)
        db.execute("INSERT INTO consultation_records (office_id,client_id,record_date,counselor_id,method,contact_type,content,response,followup) VALUES (?,?,?,?,?,?,?,?,?)",
            (oid,body.client_id,body.record_date,body.counselor_id,body.method,body.contact_type,body.content,body.response,body.followup))
        db.commit()
        cl = db.execute("SELECT name FROM clients WHERE id=?", (body.client_id,)).fetchone() if body.client_id else None
        co = db.execute("SELECT name FROM counselors WHERE id=?", (body.counselor_id,)).fetchone() if body.counselor_id else None
        off = db.execute("SELECT office_name, gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
        if off and off["gas_webhook_url"]:
            _gas_send_bg(off["gas_webhook_url"], {
                "type": "consultation", "date": body.record_date,
                "office_name": off["office_name"],
                "client_name": cl["name"] if cl else "",
                "counselor_name": co["name"] if co else "",
                "method": body.method or "",
                "content": body.content or "",
                "response": body.response or ""
            })
        return {"ok":True}
    finally:
        db.close()

@app.get("/api/handovers")
def list_handovers(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM handovers WHERE office_id=? ORDER BY created_at DESC LIMIT 50", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.post("/api/handovers")
def create_handover(body: HandoverIn, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("INSERT INTO handovers (office_id,staff_name,content,priority) VALUES (?,?,?,?)",
            (oid,body.staff_name,body.content,body.priority))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.patch("/api/handovers/{hid}/read")
def mark_handover_read(hid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("UPDATE handovers SET is_read=1 WHERE id=? AND office_id=?", (hid, oid))
        db.commit()
        return {"ok":True}
    finally:
        db.close()

@app.post("/api/doc/assessment/{client_id}")
async def gen_assessment_doc(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        client = db.execute("SELECT * FROM clients WHERE id=? AND office_id=?", (client_id,oid)).fetchone()
        if not client: raise HTTPException(404)
        assess = db.execute("SELECT * FROM assessments WHERE client_id=? AND office_id=? ORDER BY assess_date DESC LIMIT 1", (client_id,oid)).fetchone()
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key or OpenAIClient is None: return {"text":"AI機能を使用するにはOpenAI APIキーが必要です。"}
        ci=dict(client); ai=dict(assess) if assess else {}
        name=ci.get("name",""); ls=ai.get("living_situation",""); st=ai.get("strengths",""); ch=ai.get("challenges","")
        prompt=f"利用者: {name} のアセスメントシートを作成してください。生活状況: {ls}, 強み: {st}, 課題: {ch}"
        oai=OpenAIClient(api_key=api_key, timeout=30.0)
        resp=oai.chat.completions.create(model="gpt-4o-mini",messages=[{"role":"user","content":prompt}])
        return {"text":resp.choices[0].message.content}
    finally:
        db.close()

@app.post("/api/doc/plan/{client_id}")
async def gen_plan_doc(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        client = db.execute("SELECT * FROM clients WHERE id=? AND office_id=?", (client_id,oid)).fetchone()
        if not client: raise HTTPException(404)
        plan = db.execute("SELECT * FROM service_plans WHERE client_id=? AND office_id=? ORDER BY created_date DESC LIMIT 1", (client_id,oid)).fetchone()
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key or OpenAIClient is None: return {"text":"AI機能を使用するにはOpenAI APIキーが必要です。"}
        ci=dict(client); pi=dict(plan) if plan else {}
        name=ci.get("name",""); lg=pi.get("long_term_goal",""); sg=pi.get("short_term_goal","")
        prompt=f"利用者: {name} のサービス等利用計画書を作成してください。長期目標: {lg}, 短期目標: {sg}"
        oai=OpenAIClient(api_key=api_key, timeout=30.0)
        resp=oai.chat.completions.create(model="gpt-4o-mini",messages=[{"role":"user","content":prompt}])
        return {"text":resp.choices[0].message.content}
    finally:
        db.close()

@app.post("/api/doc/monitoring/{client_id}")
async def gen_monitoring_doc(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        client = db.execute("SELECT * FROM clients WHERE id=? AND office_id=?", (client_id,oid)).fetchone()
        if not client: raise HTTPException(404)
        report = db.execute("SELECT * FROM monitoring_reports WHERE client_id=? AND office_id=? ORDER BY monitor_date DESC LIMIT 1", (client_id,oid)).fetchone()
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key or OpenAIClient is None: return {"text":"AI機能を使用するにはOpenAI APIキーが必要です。"}
        ci=dict(client); ri=dict(report) if report else {}
        name=ci.get("name",""); iss=ri.get("issues","")
        prompt=f"利用者: {name} のモニタリング報告書を作成してください。課題: {iss}"
        oai=OpenAIClient(api_key=api_key, timeout=30.0)
        resp=oai.chat.completions.create(model="gpt-4o-mini",messages=[{"role":"user","content":prompt}])
        return {"text":resp.choices[0].message.content}
    finally:
        db.close()

@app.post("/api/voice-transcribe")
async def voice_transcribe(request: Request):
    import tempfile
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or OpenAIClient is None: raise HTTPException(400, "OpenAI API key not configured")
    form = await request.form()
    audio_file = form.get("audio")
    if not audio_file: raise HTTPException(400, "No audio file provided")
    with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as tmp:
        tmp.write(await audio_file.read())
        tmp_path = tmp.name
    try:
        oai = OpenAIClient(api_key=api_key, timeout=30.0)
        with open(tmp_path, "rb") as f:
            result = oai.audio.transcriptions.create(model="whisper-1", file=f)
        return {"text": result.text}
    finally:
        os.unlink(tmp_path)

@app.post("/api/ai-daily-report")
async def ai_daily_report(request: Request, oid: int = Depends(current_office)):
    db = get_db()
    check_active(oid, db)
    today = datetime.now().strftime("%Y-%m-%d")
    rows = db.execute(
        """SELECT cr.*, c.name as client_name, co.name as counselor_name
           FROM consultation_records cr
           LEFT JOIN clients c ON cr.client_id=c.id
           LEFT JOIN counselors co ON cr.counselor_id=co.id
           WHERE cr.office_id=? AND cr.record_date=?""",
        (oid, today)
    ).fetchall()
    db.close()
    if not rows:
        return JSONResponse({"report": "本日の相談記録がありません。"})
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or OpenAIClient is None:
        return JSONResponse({"report": "AI機能が利用できません。"})
    client = OpenAIClient(api_key=api_key, timeout=30.0)
    lines = []
    for r in rows:
        line = f"・{r['client_name'] or '不明'}（担当:{r['counselor_name'] or '-'}）: {r['method']} - {r['content']}"
        if r['response']: line += f" → 対応:{r['response']}"
        lines.append(line)
    summary = "\n".join(lines)
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role":"system","content":"あなたは計画相談支援事業所のサービス管理責任者です。本日の相談記録をもとに簡潔な日報を作成してください。"},
            {"role":"user","content":f"本日の相談記録:\n{summary}\n\n日報を作成してください。"}
        ],
        max_tokens=800
    )
    report_text = resp.choices[0].message.content
    today_str = today
    office = db.execute("SELECT office_name FROM offices WHERE id=?", (oid,)).fetchone() if False else None
    db3 = get_db()
    off = db3.execute("SELECT office_name, gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
    db3.close()
    office_name = off["office_name"] if off else ""
    webhook_url = off["gas_webhook_url"] if off else ""
    # メール送信
    try:
        detail_lines = "\n".join([
            f"・{r['client_name'] or ''}（担当:{r['counselor_name'] or '-'}）　{r['method']}　{r['content']}"
            for r in rows
        ])
        mail_body = f"【AI日報】{office_name} {today_str}\n\n■ 個別相談記録\n{detail_lines}\n\n■ 総評・申し送り\n{report_text}"
        send_gmail(BUG_REPORT_TO, f"【AI日報】{office_name} {today_str}", mail_body)
    except Exception:
        pass
    # スプレッドシート送信
    try:
        if webhook_url and _requests:
            gas_records = [{"member_name": r["client_name"] or "", "staff_name": r["counselor_name"] or "", "condition": "", "content": f"{r['method']} {r['content']}", "staff_notes": r.get("response","") or ""} for r in rows]
            _requests.post(webhook_url, json={"date": today_str, "office_name": office_name, "records": gas_records, "summary": report_text}, timeout=15)
    except Exception:
        pass
    return JSONResponse({"report": report_text})

class ActivateIn(BaseModel):
    target_username: str
    plan: str = "standard"
    admin_key: str

@app.post("/api/admin/activate")
def activate_office(body: ActivateIn):
    if body.admin_key != "keikaku-admin-2025": raise HTTPException(403)
    db = get_db()
    try:
        db.execute("UPDATE offices SET subscription_status='active', plan=? WHERE username=?", (body.plan, body.target_username))
        db.commit()
        return {"ok":True}
    finally:
        db.close()


@app.get("/api/office-settings")
async def get_office_settings(oid: int = Depends(current_office)):
    db = get_db()
    row = db.execute("SELECT gas_webhook_url FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    return {"gas_webhook_url": row["gas_webhook_url"] if row else ""}

@app.put("/api/office-settings")
async def update_office_settings(request: Request, oid: int = Depends(current_office)):
    body = await request.json()
    url = body.get("gas_webhook_url", "").strip()
    db = get_db()
    db.execute("UPDATE offices SET gas_webhook_url=? WHERE id=?", (url, oid))
    db.commit()
    db.close()
    return {"ok": True}

@app.get("/")
def index():
    with open("static/index.html", encoding="utf-8") as f: c2=f.read()
    return HTMLResponse(c2, headers={"Cache-Control":"no-store"})



@app.get("/lp", response_class=HTMLResponse)
@app.get("/lp/", response_class=HTMLResponse)
async def lp_page():
    with open("static/lp.html", encoding="utf-8") as f: return f.read()

@app.get("/lp_custom", response_class=HTMLResponse)
@app.get("/lp_custom/", response_class=HTMLResponse)
@app.get("/lp_custom.html", response_class=HTMLResponse)
async def lp_custom_page():
    with open("static/lp_custom.html", encoding="utf-8") as f: return f.read()



import smtplib
try:
    import requests as _requests
except ImportError:
    _requests = None
from email.mime.text import MIMEText
from email.header import Header
import threading as _threading
import copy as _copy

GMAIL_USER = os.environ.get("GMAIL_USER", "")
GMAIL_PASS = os.environ.get("GMAIL_PASS", "")
BUG_REPORT_TO = os.environ.get("BUG_REPORT_TO", "kenji.kys@gmail.com")

def _gas_send_bg(webhook_url: str, payload: dict):
    if not _requests or not webhook_url:
        return
    data = _copy.deepcopy(payload)
    def _send():
        try:
            _requests.post(webhook_url, json=data, timeout=5)
        except Exception:
            pass
    _threading.Thread(target=_send, daemon=True).start()

def send_gmail(to: str, subject: str, body: str):
    if not GMAIL_USER or not GMAIL_PASS:
        return
    import ssl
    msg = MIMEText(body, "plain", "utf-8")
    msg["From"] = f"計画相談支援Manager <{GMAIL_USER}>"
    msg["To"] = to
    msg["Subject"] = Header(subject, "utf-8").encode()
    ctx = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ctx) as s:
        s.login(GMAIL_USER, GMAIL_PASS)
        s.send_message(msg)


NM_DB_PATH = "/home/ubuntu/meet/data/booking.db"

def get_nm_db():
    import sqlite3 as _sq
    db = _sq.connect(NM_DB_PATH)
    db.row_factory = _sq.Row
    return db

def get_facility_id(office_email: str):
    try:
        db = get_nm_db()
        row = db.execute("SELECT facility_id FROM users WHERE email=?", (office_email,)).fetchone()
        db.close()
        return row["facility_id"] if row and row["facility_id"] else None
    except:
        return None


@app.get("/api/call-records")
async def list_call_records(member: Optional[str]=None, record_type: Optional[str]=None, source: Optional[str]=None, oid: int=Depends(current_office)):
    db=get_db(); row=db.execute("SELECT email FROM offices WHERE id=?",(oid,)).fetchone(); db.close()
    if not row: raise HTTPException(404)
    fid=get_facility_id(row["email"])
    if not fid: return {"records":[]}
    nm=get_nm_db(); sql="SELECT * FROM nm_call_records WHERE facility_id=?"; params=[fid]
    if member: sql+=" AND member_name LIKE ?"; params.append(f"%{member}%")
    if record_type: sql+=" AND record_type=?"; params.append(record_type)
    if source: sql+=" AND source=?"; params.append(source)
    sql+=" ORDER BY created_at DESC LIMIT 200"
    rows=nm.execute(sql,params).fetchall(); nm.close()
    return {"records":[dict(r) for r in rows]}

@app.put("/api/call-records/{record_id}")
async def update_call_record(record_id: int, req: Request, oid: int=Depends(current_office)):
    body=await req.json(); db=get_db(); row=db.execute("SELECT email FROM offices WHERE id=?",(oid,)).fetchone(); db.close()
    if not row: raise HTTPException(404)
    fid=get_facility_id(row["email"])
    if not fid: raise HTTPException(403)
    nm=get_nm_db()
    if not nm.execute("SELECT id FROM nm_call_records WHERE id=? AND facility_id=?",(record_id,fid)).fetchone():
        nm.close(); raise HTTPException(404)
    fields,params=[],[]
    for k in ["summary_text","raw_transcript","member_name","record_type"]:
        if k in body: fields.append(f"{k}=?"); params.append(body[k])
    if not fields: nm.close(); raise HTTPException(400,"no fields")
    params.append(record_id); nm.execute(f"UPDATE nm_call_records SET {', '.join(fields)} WHERE id=?",params); nm.commit(); nm.close()
    return {"ok":True}

@app.get("/api/call-records/csv")
async def export_call_records_csv(oid: int=Depends(current_office)):
    import io as _io
    db=get_db(); row=db.execute("SELECT email,office_name FROM offices WHERE id=?",(oid,)).fetchone(); db.close()
    if not row: raise HTTPException(404)
    fid=get_facility_id(row["email"]); nm=get_nm_db()
    rows=nm.execute("SELECT * FROM nm_call_records WHERE facility_id=? ORDER BY created_at DESC",(fid,)).fetchall() if fid else []; nm.close()
    out=_io.StringIO(); out.write("\ufeff"); out.write("記録ID,記録種別,対象者,担当職員,面談日,作成日時,AI要約,文字起こし\n")
    for r in rows:
        def esc(v): return '"'+str(v or '').replace('"','""').replace('\n',' ')+'"'
        out.write(f"{r['id']},{esc(r['record_type'])},{esc(r['member_name'])},{esc(r['staff_name'])},{r['interview_date'] or ''},{r['created_at'] or ''},{esc(r['summary_text'])},{esc(r['raw_transcript'])}\n")
    out.seek(0)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(out,media_type="text/csv; charset=utf-8-sig",headers={"Content-Disposition":f"attachment; filename=call_records_{oid}.csv"})


class InquiryReq(BaseModel):
    category: str = ""; title: str; body: str

@app.post("/api/inquiry")
async def inquiry(req: InquiryReq, oid: int=Depends(current_office)):
    db=get_db(); row=db.execute("SELECT office_name,email FROM offices WHERE id=?",(oid,)).fetchone(); db.close()
    office=row["office_name"] if row else f"office#{oid}"; office_email=row["email"] if row else ""
    mail_body=f"""計画相談支援Managerお問い合わせ

事業所: {office}
返信先: {office_email}
カテゴリ: {req.category or "未分類"}
件名: {req.title}

【内容】
{req.body}
"""
    try:
        send_gmail(BUG_REPORT_TO, f"【お問い合わせ】{req.title} - {office}", mail_body)
        return {"ok":True}
    except Exception as e:
        raise HTTPException(500,str(e))

class BugReportReq(BaseModel):
    category: str=""; title: str; steps: str=""; expected: str=""; actual: str=""

@app.post("/api/bug-report")
async def bug_report(req: BugReportReq, oid: int=Depends(current_office)):
    db=get_db(); row=db.execute("SELECT office_name,email FROM offices WHERE id=?",(oid,)).fetchone(); db.close()
    office=row["office_name"] if row else f"office#{oid}"
    body=f"""計画相談支援Managerバグ報告

事業所: {office}
カテゴリ: {req.category or "未分類"}
件名: {req.title}

【再現手順】
{req.steps or "（未記入）"}

【期待する動作】
{req.expected or "（未記入）"}

【実際の動作】
{req.actual or "（未記入）"}
"""
    try:
        send_gmail(BUG_REPORT_TO, f"【バグ報告】{req.title} - {office}", body)
        return {"ok":True}
    except Exception as e:
        raise HTTPException(500,str(e))

@app.get("/api/nicemeet-sso-url")
async def nicemeet_sso_url(
    room: Optional[str] = None,
    dest: Optional[str] = None,
    recordType: Optional[str] = None,
    memberName: Optional[str] = None,
    oid: int = Depends(current_office)
):
    from urllib.parse import quote
    db = get_db()
    row = db.execute("SELECT office_name, email FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    if not row: raise HTTPException(404)
    payload = {"office_name": row["office_name"], "email": row["email"] or f"keikaku_{oid}@welfare.local", "system": "keikaku", "exp": int(time.time()) + 300}
    import json as _json
    payload_b64 = base64.urlsafe_b64encode(_json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()).decode()
    sig = hmac.new(WELFARE_SSO_SECRET.encode(), payload_b64.encode(), __import__('hashlib').sha256).hexdigest()
    token = payload_b64 + "." + sig
    if dest:
        final_dest = dest
    elif room:
        extras = ("&recordType=" + quote(recordType) if recordType else "") + ("&memberName=" + quote(memberName) if memberName else "")
        final_dest = f"/?room={room}&system=keikaku&name={quote(row['office_name'])}{extras}"
    else:
        final_dest = "/record?system=keikaku"
    url = f"https://meet.gaiaarts.org/api/welfare-sso?token={quote(token)}&dest={quote(final_dest)}"
    return {"url": url}

@app.get("/api/demo-login")
async def demo_login():
    db = get_db()
    username = "demo_keikaku"
    row = db.execute("SELECT * FROM offices WHERE username=?", (username,)).fetchone()
    if not row:
        salt = secrets.token_hex(16)
        db.execute(
            "INSERT INTO offices (username,office_name,email,pw_hash,pw_salt,plan,subscription_status,trial_end) VALUES (?,?,?,?,?,?,?,NULL)",
            (username, "サンプル計画相談支援センター", "demo@example.com", hash_pw("demo123", salt), salt, "active", "active")
        )
        db.commit()
        row = db.execute("SELECT * FROM offices WHERE username=?", (username,)).fetchone()
        _seed_keikaku_demo(db, row["id"])
        db.commit()
    db.close()
    return {"token": make_token(row["id"], username), "office_name": row["office_name"]}

def _seed_keikaku_demo(db, oid):
    from datetime import datetime, timedelta, date
    today = date.today()
    today_str = today.isoformat()
    # Counselors
    db.execute("INSERT INTO counselors (office_id,name,kana,cert_acquired,is_chief,is_active) VALUES (?,?,?,?,?,?)",
        (oid, "山本 相談一", "やまもと そういち", "2018-04-01", 1, 1))
    db.execute("INSERT INTO counselors (office_id,name,kana,cert_acquired,is_chief,is_active) VALUES (?,?,?,?,?,?)",
        (oid, "中村 相談子", "なかむら そうだんこ", "2020-09-01", 0, 1))
    db.commit()
    cids = [r["id"] for r in db.execute("SELECT id FROM counselors WHERE office_id=? ORDER BY id", (oid,)).fetchall()]
    # Clients
    clients_data = [
        (cids[0],"田中 花子","たなか はなこ","female","1992-05-10","psychiatric","2級","1234567","2026-09-30","東京都世田谷区","090-1111-1111","田中 一郎","090-5555-5555","就労継続支援B型","2024-04-01","6months",(today - timedelta(days=10)).isoformat(),"",""),
        (cids[0],"鈴木 太郎","すずき たろう","male","1985-08-20","intellectual","A2","2345678","2025-12-31","東京都杉並区","090-2222-2222","","","グループホーム+就労継続B型","2023-10-01","6months",(today - timedelta(days=200)).isoformat(),"","モニタリング期限超過"),
        (cids[1],"高橋 美咲","たかはし みさき","female","2000-01-15","developmental","B1","3456789","2026-06-30","東京都練馬区","090-3333-3333","高橋 次郎","090-6666-6666","自立訓練（生活訓練）","2024-09-01","3months",(today + timedelta(days=15)).isoformat(),"",""),
        (cids[1],"渡辺 健","わたなべ けん","male","1978-11-03","physical","1級","4567890","2026-03-31","東京都板橋区","090-4444-4444","渡辺 恵","090-7777-7777","就労移行支援","2024-06-01","6months",(today + timedelta(days=45)).isoformat(),"",""),
        (cids[0],"伊藤 さくら","いとう さくら","female","1998-04-25","psychiatric","2級","5678901","2026-09-30","東京都足立区","090-8888-8888","","","就労継続支援A型","2025-01-01","6months",(today + timedelta(days=90)).isoformat(),"",""),
    ]
    for c in clients_data:
        db.execute("""INSERT INTO clients (office_id,counselor_id,name,kana,gender,birthdate,disability_type,disability_level,
            jukyusha_no,jukyusha_valid_to,address,phone,family_name,family_phone,main_service,contract_date,
            monitoring_frequency,next_monitoring_date,last_monitoring_date,notes,is_active)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)""", (oid,)+c)
    clist = [r["id"] for r in db.execute("SELECT id FROM clients WHERE office_id=? ORDER BY id", (oid,)).fetchall()]
    # Assessments
    for cid in clist[:3]:
        db.execute("""INSERT INTO assessments (office_id,client_id,assess_date,living_situation,daily_life,family_support,strengths,challenges,hopes)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (oid, cid, "2024-04-01", "家族と同居", "日常生活おおむね自立", "家族の支援あり", "明るく前向きな性格", "就労継続の不安", "安定した生活を送りたい"))
    # Service plans
    for cid in clist[:3]:
        db.execute("""INSERT INTO service_plans (office_id,client_id,plan_type,created_date,approved_date,long_term_goal,short_term_goal,notes,version)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (oid, cid, "approved", "2024-04-01", "2024-04-15", "地域での自立した生活の実現", "福祉サービスを活用した安定した生活リズムの構築", "", 1))
    # Monitoring reports (overdue for client 2)
    db.execute("""INSERT INTO monitoring_reports (office_id,client_id,monitor_date,goal_achievement,satisfaction,notes)
        VALUES (?,?,?,?,?,?)""",
        (oid, clist[0], (today - timedelta(days=190)).isoformat(), "partial", "normal", "前回モニタリング実施。目標達成に向け取り組み中。"))
    # Handovers
    db.execute("INSERT INTO handovers (office_id,staff_name,content,priority) VALUES (?,?,?,?)",
        (oid, "山本 相談一", "鈴木さんのモニタリングが期限超過しています。今週中に日程調整を行ってください。", "high"))
    db.execute("INSERT INTO handovers (office_id,staff_name,content,priority) VALUES (?,?,?,?)",
        (oid, "中村 相談子", "高橋さんの次回モニタリングが今月中旬に予定されています。事前に利用事業所へ連絡を入れること。", "normal"))



# ===== BCP管理・虐待防止・加算管理 =====
class BcpRecordReq(BaseModel):
    bcp_type: str
    is_created: Optional[int] = 0
    created_date: Optional[str] = ""
    last_review_date: Optional[str] = ""
    next_review_date: Optional[str] = ""
    staff_name: Optional[str] = ""
    notes: Optional[str] = ""

class BcpTrainingReq(BaseModel):
    training_category: str
    training_type: Optional[str] = "training"
    training_date: str
    participants_count: Optional[int] = 0
    content: Optional[str] = ""
    notes: Optional[str] = ""

class AbusePrevReq(BaseModel):
    record_type: str
    record_date: str
    attendees: Optional[str] = ""
    content: Optional[str] = ""
    next_date: Optional[str] = ""
    notes: Optional[str] = ""

class KasanReq(BaseModel):
    kasan_name: str
    units: Optional[str] = ""
    freq: Optional[str] = ""
    is_notified: Optional[int] = 0
    notify_date: Optional[str] = ""
    is_active: Optional[int] = 0
    requirement_notes: Optional[str] = ""
    notes: Optional[str] = ""

@app.get("/api/bcp")
def get_bcp(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM bcp_records WHERE office_id=? ORDER BY bcp_type", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally: db.close()

@app.post("/api/bcp")
def upsert_bcp(body: BcpRecordReq, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        ex = db.execute("SELECT id FROM bcp_records WHERE office_id=? AND bcp_type=?", (oid, body.bcp_type)).fetchone()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if ex:
            db.execute("UPDATE bcp_records SET is_created=?,created_date=?,last_review_date=?,next_review_date=?,staff_name=?,notes=?,updated_at=? WHERE id=?",
                (body.is_created,body.created_date,body.last_review_date,body.next_review_date,body.staff_name,body.notes,now,ex["id"]))
        else:
            db.execute("INSERT INTO bcp_records (office_id,bcp_type,is_created,created_date,last_review_date,next_review_date,staff_name,notes) VALUES (?,?,?,?,?,?,?,?)",
                (oid,body.bcp_type,body.is_created,body.created_date,body.last_review_date,body.next_review_date,body.staff_name,body.notes))
        db.commit()
        return {"ok": True}
    finally: db.close()

@app.get("/api/bcp-trainings")
def get_bcp_trainings(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM bcp_trainings WHERE office_id=? ORDER BY training_date DESC", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally: db.close()

@app.post("/api/bcp-trainings")
def create_bcp_training(body: BcpTrainingReq, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("INSERT INTO bcp_trainings (office_id,training_category,training_type,training_date,participants_count,content) VALUES (?,?,?,?,?,?)",
            (oid,body.training_category,body.training_type,body.training_date,body.participants_count,body.content))
        db.commit()
        return {"ok": True}
    finally: db.close()

@app.delete("/api/bcp-trainings/{tid}")
def delete_bcp_training(tid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("DELETE FROM bcp_trainings WHERE id=? AND office_id=?", (tid, oid))
        db.commit()
        return {"ok": True}
    finally: db.close()

@app.get("/api/abuse-prevention")
def get_abuse_prev(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM abuse_prevention WHERE office_id=? ORDER BY record_date DESC", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally: db.close()

@app.post("/api/abuse-prevention")
def create_abuse_prev(body: AbusePrevReq, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("INSERT INTO abuse_prevention (office_id,record_type,record_date,attendees,content,next_date) VALUES (?,?,?,?,?,?)",
            (oid,body.record_type,body.record_date,body.attendees,body.content,body.next_date))
        db.commit()
        return {"ok": True}
    finally: db.close()

@app.delete("/api/abuse-prevention/{aid}")
def delete_abuse_prev(aid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        db.execute("DELETE FROM abuse_prevention WHERE id=? AND office_id=?", (aid, oid))
        db.commit()
        return {"ok": True}
    finally: db.close()

@app.get("/api/kasan")
def get_kasan(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        rows = db.execute("SELECT * FROM kasan_records WHERE office_id=? ORDER BY kasan_name", (oid,)).fetchall()
        return [dict(r) for r in rows]
    finally: db.close()

@app.post("/api/kasan")
def upsert_kasan(body: KasanReq, request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        ex = db.execute("SELECT id FROM kasan_records WHERE office_id=? AND kasan_name=?", (oid, body.kasan_name)).fetchone()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if ex:
            db.execute("UPDATE kasan_records SET units=?,freq=?,is_notified=?,notify_date=?,is_active=?,requirement_notes=?,notes=?,updated_at=? WHERE id=?",
                (body.units,body.freq,body.is_notified,body.notify_date,body.is_active,body.requirement_notes,body.notes,now,ex["id"]))
        else:
            db.execute("INSERT INTO kasan_records (office_id,kasan_name,units,freq,is_notified,notify_date,is_active,requirement_notes) VALUES (?,?,?,?,?,?,?,?)",
                (oid,body.kasan_name,body.units,body.freq,body.is_notified,body.notify_date,body.is_active,body.requirement_notes))
        db.commit()
        return {"ok": True}
    finally: db.close()

@app.get("/api/compliance-status")
def compliance_status(request: Request):
    oid = current_office(request)
    db = get_db()
    try:
        bcp_inf = db.execute("SELECT is_created FROM bcp_records WHERE office_id=? AND bcp_type='infection'", (oid,)).fetchone()
        bcp_dis = db.execute("SELECT is_created FROM bcp_records WHERE office_id=? AND bcp_type='disaster'", (oid,)).fetchone()
        abuse_committee = db.execute("SELECT id FROM abuse_prevention WHERE office_id=? AND record_type='committee' ORDER BY record_date DESC LIMIT 1", (oid,)).fetchone()
        abuse_training = db.execute("SELECT id FROM abuse_prevention WHERE office_id=? AND record_type='training' ORDER BY record_date DESC LIMIT 1", (oid,)).fetchone()
        abuse_policy = db.execute("SELECT id FROM abuse_prevention WHERE office_id=? AND record_type='policy' ORDER BY record_date DESC LIMIT 1", (oid,)).fetchone()
        alerts = []
        if not bcp_inf or not bcp_inf["is_created"]: alerts.append("感染症BCPが未策定です（基本報酬-1%減算）")
        if not bcp_dis or not bcp_dis["is_created"]: alerts.append("自然災害BCPが未策定です（基本報酬-1%減算）")
        if not abuse_committee: alerts.append("虐待防止委員会の開催記録がありません（-1%減算）")
        if not abuse_training: alerts.append("虐待防止研修の記録がありません")
        if not abuse_policy: alerts.append("虐待防止指針の整備記録がありません")
        return {
            "bcp_infection": bool(bcp_inf and bcp_inf["is_created"]),
            "bcp_disaster": bool(bcp_dis and bcp_dis["is_created"]),
            "abuse_committee": bool(abuse_committee),
            "abuse_training": bool(abuse_training),
            "abuse_policy": bool(abuse_policy),
            "alerts": alerts,
            "reduction_risk": len([a for a in alerts if "減算" in a])
        }
    finally: db.close()



# ===== 入退院情報・医療連携記録 =====
class HospitalizationReq(BaseModel):
    client_id: int
    hospital_name: Optional[str] = ""
    admission_date: str
    notification_received_date: Optional[str] = ""
    info_provided_date: Optional[str] = ""
    info_provided_method: Optional[str] = ""
    info_provided_content: Optional[str] = ""
    conference1_date: Optional[str] = ""
    conference2_date: Optional[str] = ""
    conference3_date: Optional[str] = ""
    discharge_date: Optional[str] = ""
    discharge_conference_date: Optional[str] = ""
    status: Optional[str] = "admitted"
    notes: Optional[str] = ""

class DocSignatureReq(BaseModel):
    entity_type: str
    entity_id: int
    doc_type: str
    signer_name: Optional[str] = ""
    signed_at: str
    signature_data: str
    notes: Optional[str] = ""

@app.get("/api/hospitalizations")
def get_hospitalizations(request: Request, client_id: Optional[int] = None):
    oid = current_office(request)
    db = get_db(); check_active(oid, db)
    q = """SELECT h.*, c.name as client_name
           FROM hospitalization_records h JOIN clients c ON c.id=h.client_id
           WHERE h.office_id=?"""
    params = [oid]
    if client_id: q += " AND h.client_id=?"; params.append(client_id)
    q += " ORDER BY h.admission_date DESC"
    rows = db.execute(q, params).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/hospitalizations")
def create_hospitalization(body: HospitalizationReq, request: Request):
    oid = current_office(request)
    db = get_db(); check_active(oid, db)
    db.execute("""INSERT INTO hospitalization_records
        (office_id,client_id,hospital_name,admission_date,notification_received_date,
         info_provided_date,info_provided_method,info_provided_content,
         conference1_date,conference2_date,conference3_date,
         discharge_date,discharge_conference_date,status,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (oid,body.client_id,body.hospital_name,body.admission_date,
         body.notification_received_date,body.info_provided_date,
         body.info_provided_method,body.info_provided_content,
         body.conference1_date,body.conference2_date,body.conference3_date,
         body.discharge_date,body.discharge_conference_date,body.status,body.notes))
    db.commit(); db.close(); return {"ok": True}

@app.put("/api/hospitalizations/{hid}")
def update_hospitalization(hid: int, body: HospitalizationReq, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("""UPDATE hospitalization_records SET
        hospital_name=?,admission_date=?,notification_received_date=?,
        info_provided_date=?,info_provided_method=?,info_provided_content=?,
        conference1_date=?,conference2_date=?,conference3_date=?,
        discharge_date=?,discharge_conference_date=?,status=?,notes=?
        WHERE id=? AND office_id=?""",
        (body.hospital_name,body.admission_date,body.notification_received_date,
         body.info_provided_date,body.info_provided_method,body.info_provided_content,
         body.conference1_date,body.conference2_date,body.conference3_date,
         body.discharge_date,body.discharge_conference_date,body.status,body.notes,
         hid,oid))
    db.commit(); db.close(); return {"ok": True}

@app.delete("/api/hospitalizations/{hid}")
def delete_hospitalization(hid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("DELETE FROM hospitalization_records WHERE id=? AND office_id=?", (hid, oid))
    db.commit(); db.close(); return {"ok": True}

@app.get("/api/hospitalization-kasan")
def get_hosp_kasan(request: Request, client_id: Optional[int] = None):
    """入院時情報連携加算・退院退所加算の算定可否チェック"""
    oid = current_office(request)
    db = get_db(); check_active(oid, db)
    q = """SELECT h.*, c.name as client_name
           FROM hospitalization_records h JOIN clients c ON c.id=h.client_id
           WHERE h.office_id=?"""
    params = [oid]
    if client_id: q += " AND h.client_id=?"; params.append(client_id)
    rows = db.execute(q, params).fetchall()
    result = []
    for r in rows:
        r = dict(r)
        conf_dates = [r["conference1_date"], r["conference2_date"], r["conference3_date"]]
        conf_count = sum(1 for d in conf_dates if d)
        r["kasan_I_eligible"] = bool(r["info_provided_date"]) and r["info_provided_method"] in ["対面","ICT"]
        r["kasan_II_eligible"] = bool(r["info_provided_date"])
        r["discharge_kasan_count"] = conf_count
        r["discharge_kasan_max"] = 3
        result.append(r)
    db.close(); return result

@app.get("/api/signatures")
def get_signatures_kk(request: Request, entity_type: Optional[str] = None, entity_id: Optional[int] = None):
    oid = current_office(request)
    db = get_db()
    q = "SELECT id, entity_type, entity_id, doc_type, signer_name, signed_at, notes FROM doc_signatures WHERE office_id=?"
    params = [oid]
    if entity_type: q += " AND entity_type=?"; params.append(entity_type)
    if entity_id: q += " AND entity_id=?"; params.append(entity_id)
    q += " ORDER BY signed_at DESC"
    rows = db.execute(q, params).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.post("/api/signatures")
def create_signature_kk(body: DocSignatureReq, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("INSERT INTO doc_signatures (office_id,entity_type,entity_id,doc_type,signer_name,signed_at,signature_data,notes) VALUES (?,?,?,?,?,?,?,?)",
        (oid,body.entity_type,body.entity_id,body.doc_type,body.signer_name,body.signed_at,body.signature_data,body.notes))
    db.commit(); db.close(); return {"ok": True}

@app.get("/api/signatures/{sig_id}/data")
def get_signature_data_kk(sig_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    row = db.execute("SELECT signature_data FROM doc_signatures WHERE id=? AND office_id=?", (sig_id, oid)).fetchone()
    db.close()
    if not row: raise HTTPException(status_code=404, detail="Not found")
    return {"signature_data": row["signature_data"]}

@app.delete("/api/signatures/{sig_id}")
def delete_signature_kk(sig_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("DELETE FROM doc_signatures WHERE id=? AND office_id=?", (sig_id, oid))
    db.commit(); db.close(); return {"ok": True}



# ===== 国保連請求機能（計画相談支援） =====
# 令和6年 計画相談支援 単位数
KEIKAKU_BASE_UNITS = {
    "service_plan": 1629,       # サービス利用支援費
    "monitoring": 1357,         # 継続サービス利用支援費
}
KEIKAKU_KASAN_UNITS = {
    "初回加算": 300,
    "複数サービス利用加算": 300,
    "入院時情報連携加算(Ⅰ)": 200,
    "入院時情報連携加算(Ⅱ)": 100,
    "退院・退所加算": 200,
    "集中支援加算": 2000,
}

class BillingCalcReqKk(BaseModel):
    year: int
    month: int
    unit_price: Optional[float] = 10.00

@app.get("/api/billing/calculate")
def calc_billing_kk(request: Request, year: int, month: int, unit_price: float = 10.00):
    oid = current_office(request)
    db = get_db(); check_active(oid, db)
    month_str = f"{year}-{month:02d}"
    clients = db.execute(
        "SELECT * FROM clients WHERE office_id=? AND is_active=1", (oid,)).fetchall()
    active_kasan = db.execute(
        "SELECT kasan_name FROM kasan_records WHERE office_id=? AND is_active=1", (oid,)).fetchall()
    active_kasan_names = {r["kasan_name"] for r in active_kasan}
    results = []
    for c in clients:
        # Count service plans created this month
        plan_count = db.execute(
            "SELECT COUNT(*) FROM service_plans WHERE office_id=? AND client_id=? AND created_at LIKE ?",
            (oid, c["id"], month_str + "%")).fetchone()[0]
        # Count monitoring reports this month
        monitoring_count = db.execute(
            "SELECT COUNT(*) FROM monitoring_reports WHERE office_id=? AND client_id=? AND created_at LIKE ?",
            (oid, c["id"], month_str + "%")).fetchone()[0]
        # Count conferences this month
        conf_count = db.execute(
            "SELECT COUNT(*) FROM case_conferences WHERE office_id=? AND client_id=? AND conference_date LIKE ?",
            (oid, c["id"], month_str + "%")).fetchone()[0]
        if plan_count == 0 and monitoring_count == 0:
            continue
        # Base units
        base_units = plan_count * 1629 + monitoring_count * 1357
        kasan_units = 0; kasan_detail = []
        if "初回加算" in active_kasan_names and plan_count > 0:
            kasan_units += 300; kasan_detail.append("初回加算:300")
        if "複数サービス利用加算" in active_kasan_names and plan_count > 0:
            kasan_units += 300; kasan_detail.append("複数サービス:300")
        # Hospitalization kasan this month
        hosp_i = db.execute(
            """SELECT COUNT(*) FROM hospitalization_records
               WHERE office_id=? AND client_id=? AND info_provided_date LIKE ?
               AND info_provided_method IN ('対面','ICT')""",
            (oid, c["id"], month_str + "%")).fetchone()[0]
        hosp_ii = db.execute(
            """SELECT COUNT(*) FROM hospitalization_records
               WHERE office_id=? AND client_id=? AND info_provided_date LIKE ?
               AND info_provided_method NOT IN ('対面','ICT')""",
            (oid, c["id"], month_str + "%")).fetchone()[0]
        if hosp_i > 0: kasan_units += 200 * hosp_i; kasan_detail.append(f"入院情報連携(Ⅰ):{200*hosp_i}")
        if hosp_ii > 0: kasan_units += 100 * hosp_ii; kasan_detail.append(f"入院情報連携(Ⅱ):{100*hosp_ii}")
        # Discharge kasan
        disc = db.execute(
            """SELECT SUM(
               (CASE WHEN conference1_date LIKE ? THEN 1 ELSE 0 END) +
               (CASE WHEN conference2_date LIKE ? THEN 1 ELSE 0 END) +
               (CASE WHEN conference3_date LIKE ? THEN 1 ELSE 0 END)
               ) FROM hospitalization_records WHERE office_id=? AND client_id=?""",
            (month_str+"%", month_str+"%", month_str+"%", oid, c["id"])).fetchone()[0] or 0
        if disc > 0: kasan_units += min(disc, 3) * 200; kasan_detail.append(f"退院退所加算:{min(disc,3)*200}")
        total_units = base_units + kasan_units
        total_yen = int(total_units * unit_price)
        user_burden = int(total_yen * 0.1)
        subsidy_yen = total_yen - user_burden
        service_type = "サービス利用支援" if plan_count > 0 else "継続サービス利用支援"
        results.append({
            "client_id": c["id"],
            "client_name": c["name"],
            "jukyusha_no": c["jukyusha_no"] or "",
            "disability_type": c["disability_type"] or "",
            "service_type": service_type,
            "plan_count": plan_count,
            "monitoring_count": monitoring_count,
            "conference_count": conf_count,
            "base_units": base_units,
            "kasan_units": kasan_units,
            "kasan_detail": ", ".join(kasan_detail),
            "total_units": total_units,
            "unit_price": unit_price,
            "total_yen": total_yen,
            "user_burden": user_burden,
            "subsidy_yen": subsidy_yen,
        })
    db.close()
    return {
        "year": year, "month": month, "unit_price": unit_price,
        "client_count": len(results),
        "total_subsidy": sum(r["subsidy_yen"] for r in results),
        "total_burden": sum(r["user_burden"] for r in results),
        "total_yen": sum(r["total_yen"] for r in results),
        "items": results
    }

@app.post("/api/billing/save")
def save_billing_kk(body: BillingCalcReqKk, request: Request):
    oid = current_office(request)
    db = get_db(); check_active(oid, db)
    data = calc_billing_kk(request, body.year, body.month, body.unit_price)
    for item in data["items"]:
        db.execute("""INSERT OR REPLACE INTO billing_records
            (office_id, billing_year, billing_month, client_id, service_type,
             plan_count, monitoring_count, conference_count,
             base_units, kasan_units, total_units, unit_price, total_yen, user_burden, subsidy_yen, status)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (oid, body.year, body.month, item["client_id"], item["service_type"],
             item["plan_count"], item["monitoring_count"], item["conference_count"],
             item["base_units"], item["kasan_units"], item["total_units"],
             item["unit_price"], item["total_yen"], item["user_burden"], item["subsidy_yen"], "confirmed"))
    db.commit(); db.close()
    return {"ok": True, "saved_count": len(data["items"])}

@app.get("/api/billing/history")
def billing_history_kk(request: Request):
    oid = current_office(request)
    db = get_db()
    rows = db.execute("""SELECT billing_year, billing_month,
        COUNT(DISTINCT client_id) as client_count,
        SUM(total_units) as total_units, SUM(total_yen) as total_yen,
        SUM(subsidy_yen) as total_subsidy, MAX(created_at) as created_at, status
        FROM billing_records WHERE office_id=?
        GROUP BY billing_year, billing_month, status
        ORDER BY billing_year DESC, billing_month DESC""", (oid,)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.get("/api/billing/detail")
def billing_detail_kk(request: Request, year: int, month: int):
    oid = current_office(request)
    db = get_db()
    rows = db.execute("""SELECT br.*, c.name as client_name, c.jukyusha_no, c.disability_type
        FROM billing_records br JOIN clients c ON c.id=br.client_id
        WHERE br.office_id=? AND br.billing_year=? AND br.billing_month=?
        ORDER BY c.kana""", (oid, year, month)).fetchall()
    db.close(); return [dict(r) for r in rows]

@app.get("/api/billing/csv")
def billing_csv_kk(request: Request, year: int, month: int, token: Optional[str]=None):
    from fastapi.responses import StreamingResponse
    import io, csv as csvlib
    oid = current_office_query(request, token)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    rows = db.execute("""SELECT br.*, c.name as client_name, c.jukyusha_no, c.disability_type
        FROM billing_records br JOIN clients c ON c.id=br.client_id
        WHERE br.office_id=? AND br.billing_year=? AND br.billing_month=?
        ORDER BY c.kana""", (oid, year, month)).fetchall()
    db.close()
    buf = io.StringIO()
    writer = csvlib.writer(buf)
    writer.writerow(["請求年月", "事業所名", "受給者番号", "利用者名", "障害種別",
                     "サービス種別", "計画作成回数", "モニタリング回数", "カンファレンス回数",
                     "基本単位数", "加算単位数", "総単位数", "単価(円)", "総費用額(円)",
                     "利用者負担額(円)", "給付費(円)"])
    for r in rows:
        writer.writerow([
            f"{year}年{month}月",
            office["name"] if office else "",
            r["jukyusha_no"] or "",
            r["client_name"],
            r["disability_type"] or "",
            r["service_type"] or "",
            r["plan_count"], r["monitoring_count"], r["conference_count"],
            r["base_units"], r["kasan_units"], r["total_units"],
            r["unit_price"], r["total_yen"], r["user_burden"], r["subsidy_yen"],
        ])
    buf.seek(0)
    content = "\ufeff" + buf.getvalue()
    return StreamingResponse(
        iter([content.encode("utf-8-sig")]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=keikaku_billing_{year}{month:02d}.csv"}
    )


@app.get("/api/billing/settings")
def get_billing_settings_kk(request: Request):
    oid = current_office(request)
    db = get_db()
    row = db.execute("SELECT jigyosho_no, pref_no, service_code_plan, service_code_monitoring, tanka_unit, gas_webhook_url, office_name FROM offices WHERE id=?", (oid,)).fetchone()
    db.close()
    return dict(row) if row else {}

@app.put("/api/billing/settings")
async def update_billing_settings_kk(request: Request):
    oid = current_office(request)
    body = await request.json()
    db = get_db()
    db.execute("""UPDATE offices SET jigyosho_no=?, pref_no=?, service_code_plan=?, service_code_monitoring=?, tanka_unit=?
        WHERE id=?""", (
        body.get("jigyosho_no", ""), body.get("pref_no", ""),
        body.get("service_code_plan", "431011"),
        body.get("service_code_monitoring", "431021"),
        float(body.get("tanka_unit", 10.00)), oid))
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/billing/csv/kokuhoren")
def billing_csv_kokuhoren_kk(request: Request, year: int, month: int, token: Optional[str] = None):
    """国保連提出用CSV（HA/HB形式、ShiftJIS/CRLF）"""
    import io as _io
    from fastapi.responses import StreamingResponse as _SR
    oid = current_office_query(request, token)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    if not office or not office["jigyosho_no"]:
        db.close(); raise HTTPException(400, "事業所番号が未設定です。請求設定から登録してください。")
    billing_ym = f"{year:04d}{month:02d}"
    pref_no = (office["pref_no"] or "00").zfill(2)
    jigyosho_no = str(office["jigyosho_no"]).zfill(10)
    tanka = office["tanka_unit"] or 1140
    svc_type = "43"
    code_plan = office["service_code_plan"] or "431011"
    code_mon = office["service_code_monitoring"] or "431021"
    rows = db.execute("""SELECT br.*, c.name as client_name, c.jukyusha_no, c.futan_jogen, c.kana
        FROM billing_records br JOIN clients c ON c.id=br.client_id
        WHERE br.office_id=? AND br.billing_year=? AND br.billing_month=?
        ORDER BY c.kana""", (oid, year, month)).fetchall()
    kasan_list = db.execute("SELECT * FROM kasan_records WHERE office_id=? AND is_active=1", (oid,)).fetchall()
    db.close()
    kasan_names = {k["kasan_name"] for k in kasan_list}
    hb_lines = []; hb_count = 0; total_units = 0; total_amount = 0
    for r in rows:
        if not r["jukyusha_no"]: continue
        jno = str(r["jukyusha_no"]).zfill(10)
        if r["plan_count"] > 0:
            ku = r["plan_count"] * 1629; ka = int(ku * tanka / 100)
            futan = min(r["futan_jogen"] or 0, ka)
            hb_lines.append(f"HB,{billing_ym}01,02,{pref_no},{jigyosho_no},{jno},{r['client_name']},{billing_ym},{svc_type},{code_plan},1629,{r['plan_count']},1,{ku},{ka},0,{futan},0")
            hb_count += 1; total_units += ku; total_amount += ka
        if r["monitoring_count"] > 0:
            ku = r["monitoring_count"] * 1357; ka = int(ku * tanka / 100)
            futan = min(r["futan_jogen"] or 0, ka)
            hb_lines.append(f"HB,{billing_ym}01,02,{pref_no},{jigyosho_no},{jno},{r['client_name']},{billing_ym},{svc_type},{code_mon},1357,{r['monitoring_count']},1,{ku},{ka},0,{futan},0")
            hb_count += 1; total_units += ku; total_amount += ka
        if "初回加算" in kasan_names and r["plan_count"] > 0:
            ku = 300; ka = int(ku * tanka / 100)
            hb_lines.append(f"HB,{billing_ym}01,02,{pref_no},{jigyosho_no},{jno},{r['client_name']},{billing_ym},{svc_type},431071,300,1,1,{ku},{ka},0,0,0")
            hb_count += 1; total_units += ku; total_amount += ka
    ha = f"HA,{billing_ym}01,02,{pref_no},{jigyosho_no},{office['office_name']},{billing_ym},{hb_count:06d}"
    ft = f"FT,{hb_count:06d},{total_units:07d},{total_amount:09d}"
    content = "\r\n".join([ha] + hb_lines + [ft]) + "\r\n"
    try: encoded = content.encode("cp932")
    except UnicodeEncodeError: encoded = content.encode("cp932", errors="replace")
    fname = f"keikaku_{jigyosho_no}_{billing_ym}.csv"
    return _SR(_io.BytesIO(encoded), media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={fname}"})

@app.get("/api/billing/invoice/{year}/{month}", response_class=HTMLResponse)
def billing_invoice_kk(year: int, month: int, request: Request):
    """利用者負担金請求書（印刷用HTML）"""
    from fastapi.responses import HTMLResponse as _HR
    oid = current_office(request)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    tanka = office["tanka_unit"] or 1140
    rows = db.execute("""SELECT br.*, c.name as client_name, c.futan_jogen
        FROM billing_records br JOIN clients c ON c.id=br.client_id
        WHERE br.office_id=? AND br.billing_year=? AND br.billing_month=?
        ORDER BY c.kana""", (oid, year, month)).fetchall()
    db.close()
    next_m = month + 1 if month < 12 else 1; next_y = year if month < 12 else year + 1
    today = datetime.now().strftime("%Y年%m月%d日")
    pages = ""
    for r in rows:
        if r["plan_count"] == 0 and r["monitoring_count"] == 0: continue
        total_yen = r["total_yen"]; futan = min(r["futan_jogen"] or 0, total_yen)
        svc_label = "サービス利用支援費" if r["plan_count"] > 0 else "継続サービス利用支援費"
        pages += f"""<div style="page-break-after:always;padding:20px;font-family:'MS Mincho','游明朝',serif;font-size:11pt">
<h2 style="text-align:center;font-size:16pt;margin-bottom:20px">{year}年{month}月分　利用者負担金請求書</h2>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px">
  <tr><td style="width:30%;font-weight:bold;padding:6px;border:1px solid #000">宛先</td><td style="padding:6px;border:1px solid #000"><strong>{r['client_name']}</strong>　様</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">請求事業所</td><td style="padding:6px;border:1px solid #000">{office['office_name']}</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">サービス種別</td><td style="padding:6px;border:1px solid #000">計画相談支援（{svc_label}）</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">対象期間</td><td style="padding:6px;border:1px solid #000">{year}年{month}月</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">計画作成回数</td><td style="padding:6px;border:1px solid #000">{r['plan_count']}回</td></tr>
  <tr><td style="font-weight:bold;padding:6px;border:1px solid #000">モニタリング回数</td><td style="padding:6px;border:1px solid #000">{r['monitoring_count']}回</td></tr>
</table>
<table style="width:100%;border-collapse:collapse;margin-bottom:16px">
  <thead><tr style="background:#f0f0f0"><th style="padding:6px;border:1px solid #000;text-align:left">項目</th><th style="padding:6px;border:1px solid #000;text-align:right">金額</th></tr></thead>
  <tbody>
    <tr><td style="padding:6px;border:1px solid #000">基本費</td><td style="padding:6px;border:1px solid #000;text-align:right">{int(r['base_units']*tanka/100):,}円</td></tr>
    <tr><td style="padding:6px;border:1px solid #000">加算費</td><td style="padding:6px;border:1px solid #000;text-align:right">{int(r['kasan_units']*tanka/100):,}円</td></tr>
    <tr style="font-weight:bold"><td style="padding:6px;border:1px solid #000">給付費合計</td><td style="padding:6px;border:1px solid #000;text-align:right">{total_yen:,}円</td></tr>
    <tr style="font-weight:bold;background:#e8f4ff"><td style="padding:8px;border:2px solid #000;font-size:14pt">ご請求金額（利用者負担額）</td><td style="padding:8px;border:2px solid #000;text-align:right;font-size:14pt">{futan:,}円</td></tr>
  </tbody>
</table>
<div style="margin-top:12px;font-size:10pt">お支払い期限：{next_y}年{next_m}月25日　／　作成日：{today}</div>
<div style="margin-top:16px;text-align:right;font-size:10pt">以上よろしくお願いいたします。<br>{office['office_name']}</div>
</div>"""
    html = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="UTF-8">
<title>利用者負担金請求書 {year}年{month}月</title>
<style>body{{{{font-family:'MS Mincho','游明朝',serif}}}}@media print{{{{@page{{{{margin:15mm}}}}.no-print{{{{display:none}}}}}}}}</style>
</head><body>
<div class="no-print" style="padding:12px">
  <button onclick="window.print()" style="padding:8px 20px;background:#059669;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:13px">🖨️ 全員分を印刷</button>
</div>
{pages or '<p style="padding:20px;color:#666">対象データがありません</p>'}
</body></html>"""
    return _HR(html)




# ===== 帳票生成API (keikaku) =====
from fastapi.responses import HTMLResponse, JSONResponse

@app.get("/api/forms/service-plan/{plan_id}", response_class=HTMLResponse)
def form_service_plan(plan_id: int, request: Request, token: Optional[str]=None):
    """サービス等利用計画書（名古屋市フォーマット）"""
    oid = current_office_query(request, token)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    if office: office = dict(office)
    plan = db.execute("""SELECT sp.*, c.name as client_name, c.kana, c.birthdate, c.gender,
        c.disability_type, c.disability_level, c.jukyusha_no, c.jukyusha_valid_to,
        c.address, c.phone, c.family_name, c.family_phone, c.main_service, c.notes as client_notes,
        co.name as counselor_name
        FROM service_plans sp
        JOIN clients c ON c.id=sp.client_id
        LEFT JOIN counselors co ON co.id=c.counselor_id
        WHERE sp.id=? AND sp.office_id=?""", (plan_id, oid)).fetchone()
    if not plan: raise HTTPException(404)
    plan = dict(plan)
    from datetime import date
    today = date.today().strftime("%Y年%m月%d日")
    disability_map = {{"psychiatric":"精神障害","intellectual":"知的障害","physical":"身体障害","developmental":"発達障害","other":"その他"}}
    dis_label = disability_map.get(plan.get('disability_type',''), plan.get('disability_type',''))
    def chk(val, label):
        c = "☑" if val else "☐"
        return f"{c}&nbsp;{label}"
    dis_checks = "　".join([
        chk(plan.get('disability_type')=='physical','身体'),
        chk(plan.get('disability_type')=='intellectual','知的'),
        chk(plan.get('disability_type')=='psychiatric','精神'),
        chk(plan.get('disability_type')=='developmental','発達'),
        chk(plan.get('disability_type')=='other','難病等その他'),
    ])
    # 週間計画表: グリッドJSON → PDF反映
    import json as _json
    _grid = {}
    try: _grid = _json.loads(plan.get('weekly_grid_json','{}') or '{}')
    except: pass
    _cells = _grid.get('cells', {})
    _overview = _grid.get('overview', '') or plan.get('weekly_schedule','') or ''
    _non_weekly = _grid.get('non_weekly', '')
    label_hours = {6,8,10,12,14,16,18,20,22,0,2,4}
    all_hours = list(range(6,24)) + list(range(0,6))
    weekdays = ["月","火","水","木","金","土","日・祝"]
    def _c(h,d):
        v = _cells.get(f"h{h}_{d}",'')
        return v.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace(chr(10),'<br>') if v else '&nbsp;'
    week_rows = ""
    for h in all_hours:
        is_label = h in label_hours
        label = f"{h:02d}:00" if is_label else ""
        bg = "background:#f5f5f5;" if is_label else ""
        fw = "font-weight:600;" if is_label else ""
        row_h = "min-height:20px;" if is_label else "height:6px;"
        week_rows += f"<tr style='{row_h}'><td style='{bg}{fw}font-size:8pt;white-space:nowrap;padding:1px 3px;width:38px;vertical-align:top'>{label}</td>"
        if is_label:
            for d in weekdays:
                week_rows += f"<td style='font-size:7.5pt;padding:2px;vertical-align:top'>{_c(h,d)}</td>"
            week_rows += f"<td style='font-size:7.5pt;padding:2px;vertical-align:top;min-width:70px'>{_c(h,'活動')}</td>"
        else:
            for _ in range(8):
                week_rows += "<td style='border-top:none'></td>"
        week_rows += "</tr>"
    week_rows += f"<tr style='background:#e8e8e8'><td colspan='9' style='font-size:8pt;font-weight:700;padding:3px 6px'>週単位以外のサービス</td></tr>"
    week_rows += f"<tr><td colspan='9' style='padding:4px;font-size:8.5pt;white-space:pre-wrap'>{_non_weekly.replace('&','&amp;').replace('<','&lt;') if _non_weekly else '&nbsp;'}</td></tr>"
    services_text = plan.get("services","") or ""
    html = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<title>サービス等利用計画書 - {{plan['client_name']}}</title>
<style>
  body{{font-family:'游明朝','Hiragino Mincho ProN',serif;font-size:9.5pt;color:#000;margin:0}}
  .page{{padding:12mm 15mm;box-sizing:border-box}}
  h1{{text-align:center;font-size:13pt;border-bottom:2px solid #000;padding-bottom:6px;margin-bottom:12px}}
  h2{{font-size:10pt;background:#ddd;padding:2px 6px;margin:10px 0 4px;border-left:3px solid #555}}
  h3{{font-size:9.5pt;margin:8px 0 4px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:8px;font-size:9pt}}
  th,td{{border:1px solid #555;padding:3px 6px;vertical-align:top}}
  th{{background:#f0f0f0;font-weight:bold}}
  .box{{border:1px solid #555;padding:6px;min-height:36px;margin-bottom:6px;white-space:pre-wrap}}
  .sign-row{{display:flex;gap:20px;margin-top:16px;font-size:9pt}}
  .sign-block{{flex:1;text-align:center}}
  .sign-line{{display:inline-block;border-bottom:1px solid #000;min-width:90px}}
  @media print{{button{{display:none}}.page-break{{page-break-before:always}}}}
  button{{padding:6px 18px;background:#7c3aed;color:white;border:none;border-radius:4px;cursor:pointer;margin:8px 0;font-size:10pt}}
</style></head><body>
<div class="page">
<button onclick="window.print()">🖨️ 印刷 / PDF保存</button>

<!-- ===== 勘案事項整理票 ===== -->
<h1>勘案事項整理票</h1>
<p style="text-align:right;font-size:8pt">作成日：{{plan['created_date'] or today}}</p>
<table>
  <tr><th style="width:22%">利用者氏名</th><td><strong>{{plan['client_name']}}</strong>（{{plan.get('kana','')}}）</td>
      <th style="width:18%">生年月日</th><td>{{plan.get('birthdate','')}}</td></tr>
  <tr><th>住所</th><td colspan="3">{{plan.get('address','')}}</td></tr>
  <tr><th>障害種別</th><td colspan="3">{dis_checks}</td></tr>
  <tr><th>手帳種類・等級</th><td>&nbsp;</td>
      <th>障害支援区分</th><td>{{plan.get('disability_level','')}}</td></tr>
  <tr><th>主な介護者</th><td>{{plan.get('family_name','')}}&nbsp;（連絡先：{{plan.get('family_phone','')}}）</td>
      <th>居住環境</th><td>&nbsp;</td></tr>
  <tr><th>受給状況（サービス種類・量）</th><td colspan="3">{{plan.get('main_service','')}}　　　受給者証番号：{{plan.get('jukyusha_no','')}}　有効期限：{{plan.get('jukyusha_valid_to','')}}</td></tr>
  <tr><th>その他特記事項</th><td colspan="3">{{plan.get('client_notes','') or ''}}</td></tr>
</table>

<div class="sign-row" style="margin-top:30px">
  <div class="sign-block">相談支援事業所名：{{office['office_name'] if office else ''}}</div>
  <div class="sign-block">担当者：{{plan.get('counselor_name','')}}</div>
  <div class="sign-block">利用者同意&nbsp;署名又は捺印：<span class="sign-line">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span></div>
</div>

<!-- ===== サービス等利用計画書 ===== -->
<div class="page-break"></div>
<h1>サービス等利用計画・障害児支援利用計画</h1>
<p style="text-align:right;font-size:8pt">作成日：{{plan['created_date'] or today}}　　版：第{{plan['version'] or 1}}版</p>
<table>
  <tr><th style="width:22%">利用者氏名</th><td><strong>{{plan['client_name']}}</strong>（{{plan.get('kana','')}}）</td>
      <th style="width:18%">生年月日</th><td>{{plan.get('birthdate','')}}</td></tr>
  <tr><th>受給者証番号</th><td>{{plan.get('jukyusha_no','')}}</td>
      <th>相談支援専門員</th><td>{{plan.get('counselor_name','')}}</td></tr>
  <tr><th>相談支援事業所名</th><td colspan="3">{{office['office_name'] if office else ''}}</td></tr>
</table>

<h2>利用者及び家族の生活に対する意向（意向・希望等）</h2>
<div class="box">{{plan.get('notes','') or ''}}</div>

<h2>総合的な援助の方針</h2>
<div class="box">{{plan.get('support_policy','') or ''}}</div>

<table>
  <tr><th style="width:50%">長期目標</th><th>短期目標</th></tr>
  <tr><td style="min-height:50px"><div style="min-height:50px">{{plan.get('long_term_goal','') or ''}}</div></td>
      <td><div style="min-height:50px">{{plan.get('short_term_goal','') or ''}}</div></td></tr>
</table>

<h2>利用するサービス一覧</h2>
<table>
  <tr>
    <th style="width:20%">支援目標・達成時期</th>
    <th style="width:15%">福祉サービス等種類</th>
    <th style="width:25%">サービス内容</th>
    <th style="width:18%">提供事業者（担当者）</th>
    <th style="width:12%">頻度</th>
    <th style="width:10%">期間</th>
  </tr>
  <tr><td style="min-height:30px" colspan="6">{services_text}</td></tr>
  <tr><td>&nbsp;</td><td></td><td></td><td></td><td></td><td></td></tr>
  <tr><td>&nbsp;</td><td></td><td></td><td></td><td></td><td></td></tr>
</table>

<h2>特記事項（地域の方々との連携・その他の社会資源等）</h2>
<div class="box" style="min-height:30px">&nbsp;</div>

<div class="sign-row">
  <div class="sign-block">相談支援事業所名：{{office['office_name'] if office else ''}}</div>
  <div class="sign-block">担当者：{{plan.get('counselor_name','')}}</div>
  <div class="sign-block">計画作成日：{{plan['created_date'] or today}}</div>
  <div class="sign-block">承認日：{{plan.get('approved_date','')}}</div>
</div>
<div class="sign-row" style="margin-top:12px">
  <div class="sign-block">作成者署名：<span class="sign-line">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span></div>
  <div class="sign-block">利用者同意&nbsp;署名又は捺印：<span class="sign-line">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span></div>
</div>

<!-- ===== 週間計画表 ===== -->
<div class="page-break"></div>
<h1>サービス等利用計画案・障害児支援利用計画案【週間計画表】</h1>
<table style="font-size:8.5pt;margin-bottom:6px">
  <tr>
    <th style="width:22%">利用者氏名</th><td><strong>{{plan['client_name']}}</strong></td>
    <th style="width:18%">障害支援区分</th><td>{{plan.get('disability_level','')}}</td>
    <th style="width:18%">利用者負担額上限</th><td>&nbsp;</td>
  </tr>
  <tr>
    <th>障害福祉サービス受給者証番号</th><td>{{plan.get('jukyusha_no','')}}</td>
    <th>計画開始年月</th><td>{{(plan.get('created_date') or '')[:7]}}</td>
    <th>相談支援事業者名</th><td>{{office['office_name'] if office else ''}}</td>
  </tr>
  <tr>
    <th>地域相談支援受給者証番号</th><td>&nbsp;</td>
    <th>通所受給者証番号</th><td>&nbsp;</td>
    <th>計画作成担当者</th><td>{{plan.get('counselor_name','')}}</td>
  </tr>
</table>
<div style="font-size:8.5pt;font-weight:700;background:#ddd;padding:3px 6px;margin:4px 0 2px">サービス提供によって実現する生活の全体像</div>
<div style="border:1px solid #555;min-height:36px;padding:4px;font-size:8.5pt;margin-bottom:6px;white-space:pre-wrap">{{{_overview}}}</div>
<table style="font-size:8pt">
  <thead>
    <tr style="background:#ddd">
      <th style="width:38px">時間</th>
      <th style="text-align:center">月</th><th style="text-align:center">火</th>
      <th style="text-align:center">水</th><th style="text-align:center">木</th>
      <th style="text-align:center">金</th><th style="text-align:center">土</th>
      <th style="text-align:center">日・祝</th>
      <th>主な日常生活上の活動</th>
    </tr>
  </thead>
  <tbody>
    {week_rows}
  </tbody>
</table>

<div class="sign-row" style="margin-top:12px">
  <div class="sign-block">相談支援事業所名：{{office['office_name'] if office else ''}}</div>
  <div class="sign-block">担当者：{{plan.get('counselor_name','')}}</div>
  <div class="sign-block">利用者同意&nbsp;署名又は捺印：<span class="sign-line">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span></div>
  <div class="sign-block">日付：<span class="sign-line">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span></div>
</div>

</div>
</body></html>"""
    db.close()
    return html

@app.get("/api/forms/monitoring/{report_id}", response_class=HTMLResponse)
def form_monitoring(report_id: int, request: Request, token: Optional[str]=None):
    """モニタリング報告書（名古屋市フォーマット）"""
    oid = current_office_query(request, token)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    if office: office = dict(office)
    rep = db.execute("""SELECT mr.*, c.name as client_name, c.kana, c.birthdate,
        c.jukyusha_no, c.disability_type, c.disability_level,
        co.name as counselor_name
        FROM monitoring_reports mr
        JOIN clients c ON c.id=mr.client_id
        LEFT JOIN counselors co ON co.id=mr.counselor_id
        WHERE mr.id=? AND mr.office_id=?""", (report_id, oid)).fetchone()
    if not rep: raise HTTPException(404)
    rep = dict(rep)
    # 最新サービス計画の援助方針を参照
    latest_plan = db.execute("""SELECT support_policy, long_term_goal, short_term_goal, services
        FROM service_plans WHERE client_id=? AND office_id=?
        ORDER BY created_at DESC LIMIT 1""",
        (rep['client_id'], oid)).fetchone()
    latest_plan = dict(latest_plan) if latest_plan else {}
    achievement_map = {{"achieved":"達成","mostly":"ほぼ達成","partial":"一部達成","not":"未達成"}}
    ach = achievement_map.get(rep.get('goal_achievement',''), rep.get('goal_achievement','') or '　')
    plan_change = rep.get('plan_change','') or ''
    change_needed_yes = "☑" if plan_change and plan_change != '変更なし' else "☐"
    change_needed_no  = "☐" if plan_change and plan_change != '変更なし' else "☑"
    # サービス一覧テキストから行を生成（カンマ・改行区切りを行に）
    svc_lines = [s.strip() for s in (rep.get('service_status','') or '').replace('\r','').split('\n') if s.strip()]
    if not svc_lines:
        svc_lines = ['', '', '']
    svc_rows = ""
    for line in (svc_lines + ['',''])[:max(len(svc_lines)+1, 3)]:
        svc_rows += f"""<tr>
          <td style="min-height:24px;padding:4px 6px">{line}</td>
          <td style="padding:4px 6px">&nbsp;</td>
          <td style="padding:4px 6px">&nbsp;</td>
          <td style="text-align:center;padding:4px 6px">{ach if line == svc_lines[0] else '　'}</td>
          <td style="text-align:center;padding:4px 6px">{"有&nbsp;・&nbsp;無" if line == svc_lines[0] else '　'}</td>
        </tr>"""
    html = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<title>モニタリング報告書 - {{rep['client_name']}}</title>
<style>
  body{{font-family:'游明朝','Hiragino Mincho ProN',serif;font-size:9.5pt;color:#000;margin:0}}
  .page{{padding:12mm 15mm;box-sizing:border-box}}
  h1{{text-align:center;font-size:12pt;border-bottom:2px solid #000;padding-bottom:6px;margin-bottom:10px}}
  h2{{font-size:9.5pt;background:#ddd;padding:2px 6px;margin:8px 0 3px;border-left:3px solid #555}}
  table{{width:100%;border-collapse:collapse;margin-bottom:6px;font-size:9pt}}
  th,td{{border:1px solid #555;padding:3px 6px;vertical-align:top}}
  th{{background:#f0f0f0;font-weight:bold}}
  .box{{border:1px solid #555;padding:6px;min-height:36px;margin-bottom:6px;white-space:pre-wrap}}
  .sign-row{{display:flex;gap:16px;margin-top:12px;font-size:9pt;align-items:flex-end}}
  .sign-block{{flex:1;text-align:center}}
  .sign-line{{display:inline-block;border-bottom:1px solid #000;min-width:80px}}
  @media print{{button{{display:none}}}}
  button{{padding:6px 18px;background:#7c3aed;color:white;border:none;border-radius:4px;cursor:pointer;margin-bottom:10px;font-size:10pt}}
</style></head><body>
<div class="page">
<button onclick="window.print()">🖨️ 印刷 / PDF保存</button>
<h1>モニタリング報告書<br><span style="font-size:10pt">（継続サービス利用支援・継続障害児支援利用援助）</span></h1>

<table>
  <tr>
    <th style="width:18%">氏名</th>
    <td><strong>{{rep['client_name']}}</strong>（{{rep.get('kana','')}}）</td>
    <th style="width:20%">生年月日（年齢）</th>
    <td>{{rep.get('birthdate','')}}</td>
  </tr>
  <tr>
    <th>障害福祉サービス受給者証番号</th>
    <td>{{rep.get('jukyusha_no','')}}</td>
    <th>利用者負担上限額</th>
    <td>&nbsp;</td>
  </tr>
  <tr>
    <th>モニタリング報告書作成日</th>
    <td>{{rep.get('monitor_date','')}}</td>
    <th>モニタリング実施日（訪問日）</th>
    <td>{{rep.get('visit_date','')}}</td>
  </tr>
</table>

<h2>総合的な援助方針・全体の状況</h2>
<div class="box">{{latest_plan.get('support_policy','') or rep.get('notes','') or ''}}</div>

<h2>サービスの提供状況・支援目標の達成度</h2>
<table>
  <thead>
    <tr style="background:#e8e8e8">
      <th style="width:28%">①サービス種類<br>（福祉サービス等）</th>
      <th style="width:28%">②内容・量<br>（提供状況）</th>
      <th style="width:20%">③提供事業者<br>（担当者名）</th>
      <th style="width:12%">支援目標の<br>達成度</th>
      <th style="width:12%">変更の<br>必要</th>
    </tr>
  </thead>
  <tbody>
    {svc_rows}
  </tbody>
</table>

<h2>利用者及び家族の生活に対する意向</h2>
<div class="box" style="min-height:40px;white-space:pre-wrap">{{rep.get('client_wishes','') or ''}}</div>

<h2>生活全般の解決すべき課題（ニーズ）</h2>
<div class="box">{{rep.get('issues','') or ''}}</div>

<h2>今後の課題・解決方法、留意事項</h2>
<div class="box">{{rep.get('notes','') or ''}}</div>

<table style="margin-top:4px">
  <tr>
    <th style="width:22%">次回モニタリング予定日</th>
    <td>{{rep.get('next_monitoring','')}}</td>
    <th style="width:22%">市区町村提出</th>
    <td>{{'済' if rep.get('submitted_to_city') else '未'}}</td>
  </tr>
</table>

<div class="sign-row" style="margin-top:16px">
  <div class="sign-block" style="text-align:left">
    <div>相談支援事業所名：{{office['office_name'] if office else ''}}</div>
    <div style="margin-top:4px">計画担当者（相談支援専門員）：{{rep.get('counselor_name','')}}</div>
  </div>
  <div style="flex:0 0 180px;text-align:center;border:1px solid #555;padding:8px">
    <div style="font-size:8pt">利用者同意&nbsp;署名又は捺印</div>
    <div style="min-height:40px">&nbsp;</div>
    <div style="font-size:8pt">計画作成日：{{rep.get('monitor_date','')}}</div>
  </div>
</div>
</div>
</body></html>"""
    db.close()
    return html

# ===== ジェノグラム・エコマップ =====
class GenogramMemberReq(BaseModel):
    client_id: int
    member_type: str  # 'client','parent','spouse','child','sibling','grandparent','other'
    name: Optional[str] = ""
    gender: Optional[str] = "unknown"  # 'male','female','unknown'
    age: Optional[int] = None
    is_deceased: Optional[int] = 0
    is_cohabiting: Optional[int] = 0
    relationship_to_client: Optional[str] = ""
    x_pos: Optional[int] = 0
    y_pos: Optional[int] = 0
    notes: Optional[str] = ""

class GenogramRelReq(BaseModel):
    client_id: int
    member1_id: int
    member2_id: int
    rel_type: str  # 'married','divorced','separated','partner','parent_child','sibling','conflict','close','distant'

class EcomapItemReq(BaseModel):
    client_id: int
    item_name: str
    item_type: str  # 'service','medical','family','friend','work','education','other'
    strength: str  # 'strong','moderate','weak','stressed'
    direction: str  # 'both','to_client','from_client'
    notes: Optional[str] = ""

@app.get("/api/genogram/{client_id}")
def get_genogram(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    members = db.execute("SELECT * FROM genogram_members WHERE office_id=? AND client_id=?", (oid, client_id)).fetchall()
    rels = db.execute("SELECT * FROM genogram_relations WHERE office_id=? AND client_id=?", (oid, client_id)).fetchall()
    db.close()
    return {"members": [dict(m) for m in members], "relations": [dict(r) for r in rels]}

@app.post("/api/genogram/member")
def save_genogram_member(body: GenogramMemberReq, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("""INSERT INTO genogram_members
        (office_id,client_id,member_type,name,gender,age,is_deceased,is_cohabiting,
         relationship_to_client,x_pos,y_pos,notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
        (oid,body.client_id,body.member_type,body.name,body.gender,body.age,
         body.is_deceased,body.is_cohabiting,body.relationship_to_client,
         body.x_pos,body.y_pos,body.notes))
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit(); db.close()
    return {"ok": True, "id": new_id}

@app.put("/api/genogram/member/{mid}")
def update_genogram_member(mid: int, body: GenogramMemberReq, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("""UPDATE genogram_members SET
        name=?,gender=?,age=?,is_deceased=?,is_cohabiting=?,
        relationship_to_client=?,x_pos=?,y_pos=?,notes=?
        WHERE id=? AND office_id=?""",
        (body.name,body.gender,body.age,body.is_deceased,body.is_cohabiting,
         body.relationship_to_client,body.x_pos,body.y_pos,body.notes,mid,oid))
    db.commit(); db.close()
    return {"ok": True}

@app.delete("/api/genogram/member/{mid}")
def delete_genogram_member(mid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("DELETE FROM genogram_members WHERE id=? AND office_id=?", (mid, oid))
    db.execute("DELETE FROM genogram_relations WHERE (member1_id=? OR member2_id=?) AND office_id=?", (mid, mid, oid))
    db.commit(); db.close()
    return {"ok": True}

@app.post("/api/genogram/relation")
def save_genogram_relation(body: GenogramRelReq, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("""INSERT INTO genogram_relations (office_id,client_id,member1_id,member2_id,rel_type)
        VALUES (?,?,?,?,?)""", (oid,body.client_id,body.member1_id,body.member2_id,body.rel_type))
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit(); db.close()
    return {"ok": True, "id": new_id}

@app.delete("/api/genogram/relation/{rid}")
def delete_genogram_relation(rid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("DELETE FROM genogram_relations WHERE id=? AND office_id=?", (rid, oid))
    db.commit(); db.close()
    return {"ok": True}

@app.get("/api/ecomap/{client_id}")
def get_ecomap(client_id: int, request: Request):
    oid = current_office(request)
    db = get_db()
    items = db.execute("SELECT * FROM ecomap_items WHERE office_id=? AND client_id=?", (oid, client_id)).fetchall()
    db.close()
    return [dict(i) for i in items]

@app.post("/api/ecomap/item")
def save_ecomap_item(body: EcomapItemReq, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("""INSERT INTO ecomap_items (office_id,client_id,item_name,item_type,strength,direction,notes)
        VALUES (?,?,?,?,?,?,?)""",
        (oid,body.client_id,body.item_name,body.item_type,body.strength,body.direction,body.notes))
    new_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.commit(); db.close()
    return {"ok": True, "id": new_id}

@app.delete("/api/ecomap/item/{iid}")
def delete_ecomap_item(iid: int, request: Request):
    oid = current_office(request)
    db = get_db()
    db.execute("DELETE FROM ecomap_items WHERE id=? AND office_id=?", (iid, oid))
    db.commit(); db.close()
    return {"ok": True}

# ===== 複数事業所ダッシュボード（管理者用） =====
ADMIN_KEY = os.environ.get("ADMIN_KEY", "keikaku-admin-2025")

@app.get("/api/admin/offices")
def admin_offices(request: Request, admin_key: str = ""):
    if not __import__("hmac").compare_digest(admin_key or "", ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Forbidden")
    db = get_db()
    offices = db.execute("SELECT * FROM offices ORDER BY created_at DESC").fetchall()
    result = []
    for o in offices:
        client_count = db.execute("SELECT COUNT(*) FROM clients WHERE office_id=? AND is_active=1", (o["id"],)).fetchone()[0]
        plan_count = db.execute("SELECT COUNT(*) FROM service_plans WHERE office_id=?", (o["id"],)).fetchone()[0]
        last_active = db.execute("SELECT MAX(created_at) FROM monitoring_reports WHERE office_id=?", (o["id"],)).fetchone()[0]
        total_subsidy = db.execute("SELECT COALESCE(SUM(subsidy_yen),0) FROM billing_records WHERE office_id=?", (o["id"],)).fetchone()[0]
        result.append({**dict(o), "client_count": client_count, "plan_count": plan_count,
                       "last_active": last_active, "total_subsidy": total_subsidy})
    db.close()
    return result

@app.get("/{path:path}")
def catch_all(path: str):
    with open("static/index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

# ── person photo endpoints ──────────────────────────────────

@app.put("/api/clients/{cid}/photo")
async def upload_client_photo(cid: int, file: UploadFile = File(...), oid: int = Depends(current_office)):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, "画像ファイルのみアップロードできます")
    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(400, "10MB以下にしてください")
    if not any(data[:len(m)] == m for m in (b'\xff\xd8\xff', b'\x89PNG', b'RIFF', b'GIF8', b'GIF9')):
        raise HTTPException(400, "有効な画像ファイルではありません")
    import base64 as _b64
    photo_url = "data:image/jpeg;base64," + _b64.b64encode(data).decode()
    db = get_db()
    cur = db.execute("UPDATE clients SET photo_url=? WHERE id=? AND office_id=?", (photo_url, cid, oid))
    if cur.rowcount == 0:
        db.close()
        raise HTTPException(404, "対象が見つかりません")
    db.commit()
    db.close()
    return {"photo_url": photo_url}

@app.put("/api/counselors/{cid2}/photo")
async def upload_counselor_photo(cid2: int, file: UploadFile = File(...), oid: int = Depends(current_office)):
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(400, "画像ファイルのみアップロードできます")
    data = await file.read()
    if len(data) > MAX_SIZE:
        raise HTTPException(400, "10MB以下にしてください")
    if not any(data[:len(m)] == m for m in (b'\xff\xd8\xff', b'\x89PNG', b'RIFF', b'GIF8', b'GIF9')):
        raise HTTPException(400, "有効な画像ファイルではありません")
    import base64 as _b64
    photo_url = "data:image/jpeg;base64," + _b64.b64encode(data).decode()
    db = get_db()
    cur = db.execute("UPDATE counselors SET photo_url=? WHERE id=? AND office_id=?", (photo_url, cid2, oid))
    if cur.rowcount == 0:
        db.close()
        raise HTTPException(404, "対象が見つかりません")
    db.commit()
    db.close()
    return {"photo_url": photo_url}
