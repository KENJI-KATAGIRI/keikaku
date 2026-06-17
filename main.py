from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, hashlib, secrets, os, time, hmac, base64, json
from datetime import datetime, timedelta, date
from jose import jwt
try:
    from openai import OpenAI as OpenAIClient
except ImportError:
    OpenAIClient = None

from database import get_db, init_db

SECRET_KEY = "keikaku-manager-secret-2025"
ALGORITHM  = "HS256"
BASE_PATH  = "/keikaku"

app = FastAPI(root_path=BASE_PATH)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()
app.mount("/static", StaticFiles(directory="static"), name="static")

def hash_pw(pw, salt):
    return hashlib.sha256((pw+salt).encode()).hexdigest()

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
def register(body: RegisterIn):
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
def login(body: LoginIn):
    db = get_db()
    try:
        row = db.execute("SELECT * FROM offices WHERE username=?", (body.username,)).fetchone()
        if not row: raise HTTPException(401, "invalid credentials")
        if hash_pw(body.password, row["pw_salt"]) != row["pw_hash"]: raise HTTPException(401, "invalid credentials")
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
            short_term_goal,support_policy,weekly_schedule,services,notes,version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (oid,body.client_id,body.plan_type,body.created_date,body.approved_date,
             body.long_term_goal,body.short_term_goal,body.support_policy,body.weekly_schedule,
             body.services,body.notes,body.version))
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
            support_policy=?,weekly_schedule=?,services=?,notes=?,version=? WHERE id=? AND office_id=?""",
            (body.plan_type,body.created_date,body.approved_date,body.long_term_goal,body.short_term_goal,
             body.support_policy,body.weekly_schedule,body.services,body.notes,body.version,pid,oid))
        db.commit()
        return {"ok":True}
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
            satisfaction,service_status,issues,plan_change,next_monitoring,notes,submitted_to_city)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (oid,body.client_id,body.monitor_date,body.visit_date,body.counselor_id,
             body.goal_achievement,body.satisfaction,body.service_status,body.issues,
             body.plan_change,body.next_monitoring,body.notes,body.submitted_to_city))
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
            service_status=?,issues=?,plan_change=?,next_monitoring=?,notes=?,submitted_to_city=?
            WHERE id=? AND office_id=?""",
            (body.monitor_date,body.visit_date,body.counselor_id,body.goal_achievement,body.satisfaction,
             body.service_status,body.issues,body.plan_change,body.next_monitoring,body.notes,
             body.submitted_to_city,rid,oid))
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
        oai=OpenAIClient(api_key=api_key)
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
        oai=OpenAIClient(api_key=api_key)
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
        oai=OpenAIClient(api_key=api_key)
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
    audio_file = form.get("file")
    if not audio_file: raise HTTPException(400, "No audio file provided")
    with tempfile.NamedTemporaryFile(suffix=".webm", delete=False) as tmp:
        tmp.write(await audio_file.read())
        tmp_path = tmp.name
    try:
        oai = OpenAIClient(api_key=api_key)
        with open(tmp_path, "rb") as f:
            result = oai.audio.transcriptions.create(model="whisper-1", file=f)
        return {"text": result.text}
    finally:
        os.unlink(tmp_path)

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

@app.get("/api/admin/offices")
def list_offices(admin_key: str = ""):
    if admin_key != "keikaku-admin-2025": raise HTTPException(403)
    db = get_db()
    try:
        rows = db.execute("SELECT id,username,office_name,email,plan,subscription_status,trial_end,created_at FROM offices ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()

@app.get("/")
def index():
    with open("static/index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())



@app.get("/lp", response_class=HTMLResponse)
@app.get("/lp/", response_class=HTMLResponse)
async def lp_page():
    with open("static/lp.html", encoding="utf-8") as f: return f.read()

@app.get("/lp_custom", response_class=HTMLResponse)
@app.get("/lp_custom/", response_class=HTMLResponse)
@app.get("/lp_custom.html", response_class=HTMLResponse)
async def lp_custom_page():
    with open("static/lp_custom.html", encoding="utf-8") as f: return f.read()


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



# ===== 帳票生成API (keikaku) =====
from fastapi.responses import HTMLResponse

@app.get("/api/forms/service-plan/{plan_id}", response_class=HTMLResponse)
def form_service_plan(plan_id: int, request: Request, token: Optional[str]=None):
    """サービス等利用計画書"""
    oid = current_office_query(request, token)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    if office: office = dict(office)
    plan = db.execute("SELECT sp.*, c.name as client_name, c.kana, c.birthdate, c.gender, c.disability_type, c.disability_level, c.jukyusha_no, c.address, co.name as counselor_name FROM service_plans sp JOIN clients c ON c.id=sp.client_id LEFT JOIN counselors co ON co.id=c.counselor_id WHERE sp.id=? AND sp.office_id=?", (plan_id, oid)).fetchone()
    if not plan: raise HTTPException(404)
    plan = dict(plan)
    from datetime import date
    today = date.today().strftime("%Y年%m月%d日")
    disability_map = {"psychiatric":"精神障害","intellectual":"知的障害","physical":"身体障害","developmental":"発達障害","other":"その他"}
    services_text = plan["services"] or ""
    html = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<title>サービス等利用計画書 - {plan['client_name']}</title>
<style>
  body{{font-family:'游明朝','Hiragino Mincho ProN',serif;padding:15mm;font-size:10pt;color:#000;margin:0}}
  h1{{text-align:center;font-size:15pt;border-bottom:2px solid #000;padding-bottom:8px;margin-bottom:16px}}
  h2{{font-size:11pt;background:#e8e8e8;padding:3px 8px;border-left:4px solid #555;margin:14px 0 6px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:10px;font-size:9.5pt}}
  th,td{{border:1px solid #666;padding:5px 8px;vertical-align:top}}
  th{{background:#f0f0f0;font-weight:bold;width:22%}}
  .goal-box{{border:1px solid #666;padding:8px;min-height:45px;margin-bottom:10px}}
  @media print{{button{{display:none}}}}
  button{{padding:8px 20px;background:#7c3aed;color:white;border:none;border-radius:4px;cursor:pointer;margin-bottom:12px}}
</style></head><body>
<button onclick="window.print()">🖨️ 印刷 / PDF保存</button>
<h1>サービス等利用計画書</h1>
<p style="text-align:right;font-size:9pt">作成日：{plan['created_date'] or today}　　版：第{plan['version'] or 1}版</p>
<table>
  <tr><th>利用者氏名</th><td><strong>{plan['client_name']}</strong>（{plan.get('kana','')}&nbsp;）</td>
      <th>生年月日</th><td>{plan.get('birthdate','')}</td></tr>
  <tr><th>障害種別</th><td>{disability_map.get(plan.get('disability_type',''),'')}</td>
      <th>障害支援区分</th><td>{plan.get('disability_level','')}</td></tr>
  <tr><th>受給者番号</th><td>{plan.get('jukyusha_no','')}</td>
      <th>相談支援専門員</th><td>{plan.get('counselor_name','')}</td></tr>
  <tr><th>住所</th><td colspan="3">{plan.get('address','')}</td></tr>
</table>
<h2>総合的な支援の方針</h2>
<div class="goal-box">{plan.get('support_policy','') or ''}</div>
<h2>長期目標</h2>
<div class="goal-box">{plan.get('long_term_goal','') or ''}</div>
<h2>短期目標</h2>
<div class="goal-box">{plan.get('short_term_goal','') or ''}</div>
<h2>週間計画・利用サービス</h2>
<div class="goal-box" style="min-height:80px">{plan.get('weekly_schedule','') or ''}</div>
<h2>利用するサービス一覧</h2>
<div class="goal-box">{services_text}</div>
<h2>特記事項</h2>
<div class="goal-box">{plan.get('notes','') or ''}</div>
<table style="margin-top:20px">
  <tr>
    <td style="border:none;text-align:center">事業所：{office['office_name'] if office else ''}</td>
    <td style="border:none;text-align:center">作成者署名：<span style="display:inline-block;border-bottom:1px solid #000;min-width:80px">&nbsp;</span></td>
    <td style="border:none;text-align:center">利用者同意署名：<span style="display:inline-block;border-bottom:1px solid #000;min-width:80px">&nbsp;</span></td>
    <td style="border:none;text-align:center">承認日：{plan.get('approved_date','')}</td>
  </tr>
</table>
</body></html>"""
    db.close()
    return html

@app.get("/api/forms/monitoring/{report_id}", response_class=HTMLResponse)
def form_monitoring(report_id: int, request: Request, token: Optional[str]=None):
    """モニタリング報告書"""
    oid = current_office_query(request, token)
    db = get_db()
    office = db.execute("SELECT * FROM offices WHERE id=?", (oid,)).fetchone()
    if office: office = dict(office)
    rep = db.execute("""SELECT mr.*, c.name as client_name, c.jukyusha_no, c.disability_type,
        co.name as counselor_name FROM monitoring_reports mr
        JOIN clients c ON c.id=mr.client_id
        LEFT JOIN counselors co ON co.id=mr.counselor_id
        WHERE mr.id=? AND mr.office_id=?""", (report_id, oid)).fetchone()
    if not rep: raise HTTPException(404)
    rep = dict(rep)
    satisfaction_map = {"very_satisfied":"非常に満足","satisfied":"満足","neutral":"普通","unsatisfied":"不満","very_unsatisfied":"非常に不満"}
    achievement_map = {"achieved":"達成","mostly":"ほぼ達成","partial":"一部達成","not":"未達成"}
    html = f"""<!DOCTYPE html><html lang="ja"><head><meta charset="utf-8">
<title>モニタリング報告書 - {rep['client_name']}</title>
<style>
  body{{font-family:'游明朝','Hiragino Mincho ProN',serif;padding:15mm;font-size:10pt;color:#000;margin:0}}
  h1{{text-align:center;font-size:15pt;border-bottom:2px solid #000;padding-bottom:8px;margin-bottom:16px}}
  h2{{font-size:11pt;background:#e8e8e8;padding:3px 8px;border-left:4px solid #555;margin:14px 0 6px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:10px}}
  th,td{{border:1px solid #666;padding:5px 8px;vertical-align:top}}
  th{{background:#f0f0f0;font-weight:bold;width:28%}}
  .content-box{{border:1px solid #666;padding:8px;min-height:40px;margin-bottom:10px}}
  @media print{{button{{display:none}}}}
  button{{padding:8px 20px;background:#7c3aed;color:white;border:none;border-radius:4px;cursor:pointer;margin-bottom:12px}}
</style></head><body>
<button onclick="window.print()">🖨️ 印刷 / PDF保存</button>
<h1>継続サービス利用支援（モニタリング）報告書</h1>
<table>
  <tr><th>利用者氏名</th><td><strong>{rep['client_name']}</strong></td>
      <th>受給者番号</th><td>{rep.get('jukyusha_no','')}</td></tr>
  <tr><th>モニタリング実施日</th><td>{rep.get('monitor_date','')}</td>
      <th>訪問日</th><td>{rep.get('visit_date','')}</td></tr>
  <tr><th>相談支援専門員</th><td>{rep.get('counselor_name','')}</td>
      <th>事業所</th><td>{office['office_name'] if office else ''}</td></tr>
</table>
<h2>目標達成度</h2>
<table>
  <tr><th>目標達成状況</th><td>{achievement_map.get(rep.get('goal_achievement',''),'')}</td>
      <th>本人満足度</th><td>{satisfaction_map.get(rep.get('satisfaction',''),'')}</td></tr>
</table>
<h2>サービス利用状況</h2>
<div class="content-box">{rep.get('service_status','') or ''}</div>
<h2>課題・問題点</h2>
<div class="content-box">{rep.get('issues','') or ''}</div>
<h2>計画変更の必要性</h2>
<div class="content-box">{rep.get('plan_change','') or '変更なし'}</div>
<h2>特記事項</h2>
<div class="content-box">{rep.get('notes','') or ''}</div>
<table style="margin-top:16px">
  <tr><th>次回モニタリング予定日</th><td>{rep.get('next_monitoring','')}</td>
      <th>市区町村提出</th><td>{'済' if rep.get('submitted_to_city') else '未'}</td></tr>
</table>
<div style="margin-top:24px;text-align:right">
  作成者署名：<span style="display:inline-block;border-bottom:1px solid #000;min-width:100px">&nbsp;</span>&nbsp;&nbsp;
  利用者確認署名：<span style="display:inline-block;border-bottom:1px solid #000;min-width:100px">&nbsp;</span>
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
    if admin_key != ADMIN_KEY:
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
