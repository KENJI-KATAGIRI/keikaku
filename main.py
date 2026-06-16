from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sqlite3, hashlib, secrets, os, json
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

@app.get("/{path:path}")
def catch_all(path: str):
    with open("static/index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())
