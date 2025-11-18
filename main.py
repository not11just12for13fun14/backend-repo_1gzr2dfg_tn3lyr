import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User as UserSchema, Session as SessionSchema, Department as DepartmentSchema, Employee as EmployeeSchema, Attendance as AttendanceSchema, Leave as LeaveSchema, Payroll as PayrollSchema, Project as ProjectSchema, Task as TaskSchema, Notification as NotificationSchema, Document as DocumentSchema


app = FastAPI(title="Employee Management System API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------- Utils -----------------------

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def serialize(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    d = {**doc}
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    for k, v in list(d.items()):
        if isinstance(v, ObjectId):
            d[k] = str(v)
        if isinstance(v, (datetime, date)):
            d[k] = v.isoformat()
    return d


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000).hex()
    return f"{salt}${h}"


def verify_password(password: str, password_hash: str) -> bool:
    try:
        salt, h = password_hash.split('$')
        check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100_000).hex()
        return secrets.compare_digest(h, check)
    except Exception:
        return False


# ----------------------- Auth Models -----------------------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: Optional[str] = 'employee'

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class AuthUser(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str
    is_active: bool


# ----------------------- Auth Helpers -----------------------

def get_user_by_email(email: str) -> Optional[dict]:
    return db['user'].find_one({"email": email})


def create_session(user_id: str, user_agent: Optional[str], ip: Optional[str]) -> str:
    token = secrets.token_urlsafe(32)
    sess = SessionSchema(
        user_id=user_id,
        token=token,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        user_agent=user_agent,
        ip=ip
    )
    create_document('session', sess)
    return token


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(' ', 1)[1]
    sess = db['session'].find_one({"token": token})
    if not sess:
        raise HTTPException(status_code=401, detail="Invalid session")
    if sess.get('expires_at') and sess['expires_at'] < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Session expired")
    user = db['user'].find_one({"_id": oid(sess['user_id']) if isinstance(sess['user_id'], str) else sess['user_id']})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_roles(*roles: str):
    def dep(user: dict = Depends(get_current_user)):
        if user.get('role') not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return dep


# ----------------------- Routes: Health -----------------------
@app.get("/")
def read_root():
    return {"message": "EMS Backend running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            try:
                response["collections"] = db.list_collection_names()[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:50]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


# ----------------------- Auth -----------------------
@app.post('/auth/signup')
def signup(payload: SignupRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role if payload.role in ['admin','hr','lead','employee'] else 'employee',
    )
    user_id = create_document('user', user)
    token = create_session(user_id, None, None)
    return {
        "token": token,
        "user": serialize({"_id": oid(user_id), **user.model_dump()})
    }

@app.post('/auth/login')
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user or not verify_password(payload.password, user.get('password_hash','')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get('is_active', True):
        raise HTTPException(status_code=403, detail="Account disabled")
    token = create_session(str(user['_id']), None, None)
    db['user'].update_one({"_id": user['_id']}, {"$set": {"last_login_at": datetime.now(timezone.utc)}})
    return {"token": token, "user": serialize(user)}

@app.get('/auth/me')
def me(user: dict = Depends(get_current_user)):
    return serialize(user)

@app.post('/auth/logout')
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith('bearer '):
        token = authorization.split(' ', 1)[1]
        db['session'].delete_many({"token": token})
    return {"ok": True}


# ----------------------- Admin Dashboard -----------------------
@app.get('/admin/stats')
def admin_stats(_: dict = Depends(require_roles('admin','hr'))):
    total_users = db['user'].count_documents({})
    total_employees = db['employee'].count_documents({})
    total_departments = db['department'].count_documents({})
    active_users = db['user'].count_documents({"is_active": True})
    payroll_sum = sum([p.get('net_pay', 0) for p in db['payroll'].find({})])
    recent_activity = [
        serialize(x) for x in db['notification'].find({}).sort('created_at', -1).limit(10)
    ]
    return {
        "cards": {
            "employees": total_employees,
            "departments": total_departments,
            "active_users": active_users,
            "payroll_expenses": payroll_sum,
        },
        "recent_activity": recent_activity,
        "charts": {
            "attendance": [],
            "performance": [],
            "payroll": []
        }
    }


# ----------------------- Employees -----------------------
class EmployeeCreate(BaseModel):
    name: str
    email: EmailStr
    phone: Optional[str] = None
    address: Optional[str] = None
    designation: Optional[str] = None
    department_id: Optional[str] = None
    salary: float = 0

@app.get('/employees')
def list_employees(_: dict = Depends(require_roles('admin','hr','lead')),
                   q: Optional[str] = Query(None), limit: int = 100):
    filt: Dict[str, Any] = {}
    if q:
        filt["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"email": {"$regex": q, "$options": "i"}},
        ]
    users = list(db['user'].find(filt).limit(limit))
    # join with employee profile
    emp_map = {str(e['user_id']): e for e in db['employee'].find({})}
    out = []
    for u in users:
        e = emp_map.get(str(u['_id']))
        merged = {**serialize(u), **({k: v for k, v in e.items() if k != '_id'} if e else {})}
        out.append(merged)
    return out

@app.post('/employees')
def add_employee(payload: EmployeeCreate, _: dict = Depends(require_roles('admin','hr'))):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already exists")
    password = secrets.token_urlsafe(8)
    user = UserSchema(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(password),
        role='employee'
    )
    user_id = create_document('user', user)
    employee = EmployeeSchema(
        user_id=user_id,
        employee_code=f"EMP-{str(user_id)[-6:]}",
        phone=payload.phone,
        address=payload.address,
        designation=payload.designation,
        department_id=payload.department_id,
        salary=payload.salary,
    )
    create_document('employee', employee)
    return {"message": "Employee created", "temp_password": password}

@app.get('/employees/{user_id}')
def get_employee(user_id: str, _: dict = Depends(require_roles('admin','hr','lead','employee'))):
    user = db['user'].find_one({"_id": oid(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="Not found")
    emp = db['employee'].find_one({"user_id": user_id})
    return {**serialize(user), **(serialize(emp) if emp else {})}

@app.put('/employees/{user_id}')
def update_employee(user_id: str, payload: Dict[str, Any], current: dict = Depends(require_roles('admin','hr'))):
    allowed_user_fields = {"name", "email", "is_active", "role"}
    allowed_emp_fields = {"phone","address","designation","department_id","salary","status"}
    if any(k in payload for k in allowed_user_fields):
        db['user'].update_one({"_id": oid(user_id)}, {"$set": {k: v for k, v in payload.items() if k in allowed_user_fields}})
    if any(k in payload for k in allowed_emp_fields):
        db['employee'].update_one({"user_id": user_id}, {"$set": {k: v for k, v in payload.items() if k in allowed_emp_fields}}, upsert=True)
    return {"ok": True}

@app.delete('/employees/{user_id}')
def delete_employee(user_id: str, _: dict = Depends(require_roles('admin','hr'))):
    db['employee'].delete_many({"user_id": user_id})
    db['user'].delete_one({"_id": oid(user_id)})
    return {"ok": True}


# Bulk upload via CSV (basic)
class CSVUpload(BaseModel):
    rows: List[Dict[str, Any]]

@app.post('/employees/bulk')
def bulk_upload(payload: CSVUpload, _: dict = Depends(require_roles('admin','hr'))):
    created = 0
    for row in payload.rows:
        try:
            ec = EmployeeCreate(**row)
            add_employee(ec)  # type: ignore
            created += 1
        except Exception:
            continue
    return {"created": created, "total": len(payload.rows)}


# ----------------------- Departments -----------------------
@app.get('/departments')
def list_departments(_: dict = Depends(require_roles('admin','hr','lead','employee'))):
    return [serialize(x) for x in db['department'].find({})]

@app.post('/departments')
def create_department(payload: DepartmentSchema, _: dict = Depends(require_roles('admin','hr'))):
    dep_id = create_document('department', payload)
    return {"id": dep_id}


# ----------------------- Attendance & Leave -----------------------
@app.post('/attendance/clock-in')
def clock_in(user: dict = Depends(require_roles('admin','hr','lead','employee'))):
    today = date.today().isoformat()
    exists = db['attendance'].find_one({"user_id": str(user['_id']), "date": today})
    if exists and exists.get('clock_in'):
        raise HTTPException(status_code=400, detail="Already clocked in")
    att = {
        "user_id": str(user['_id']),
        "date": today,
        "clock_in": datetime.now(timezone.utc)
    }
    db['attendance'].update_one({"user_id": att['user_id'], "date": today}, {"$set": att}, upsert=True)
    return {"ok": True}

@app.post('/attendance/clock-out')
def clock_out(user: dict = Depends(require_roles('admin','hr','lead','employee'))):
    today = date.today().isoformat()
    att = db['attendance'].find_one({"user_id": str(user['_id']), "date": today})
    if not att or not att.get('clock_in'):
        raise HTTPException(status_code=400, detail="Not clocked in")
    db['attendance'].update_one({"_id": att['_id']}, {"$set": {"clock_out": datetime.now(timezone.utc)}})
    return {"ok": True}

@app.get('/attendance')
def get_attendance(user_id: Optional[str] = None, month: Optional[int] = None, year: Optional[int] = None, _: dict = Depends(require_roles('admin','hr','lead','employee'))):
    filt: Dict[str, Any] = {}
    if user_id:
        filt['user_id'] = user_id
    if month and year:
        prefix = f"{year:04d}-{month:02d}-"
        filt['date'] = {"$regex": f"^{prefix}"}
    return [serialize(x) for x in db['attendance'].find(filt).sort('date', -1)]

# Leave
class LeaveCreate(BaseModel):
    start_date: date
    end_date: date
    reason: Optional[str] = None

@app.post('/leave/apply')
def apply_leave(payload: LeaveCreate, user: dict = Depends(require_roles('admin','hr','lead','employee'))):
    leave = LeaveSchema(
        user_id=str(user['_id']),
        start_date=payload.start_date,
        end_date=payload.end_date,
        reason=payload.reason,
    )
    lid = create_document('leave', leave)
    # notify HR
    db['notification'].insert_one({
        "user_id": None,
        "type": "leave",
        "title": "Leave Request",
        "message": f"{user['name']} requested leave {payload.start_date} to {payload.end_date}",
        "is_read": False,
        "created_at": datetime.now(timezone.utc)
    })
    return {"id": lid}

class LeaveAction(BaseModel):
    status: str

@app.post('/leave/{leave_id}/action')
def approve_leave(leave_id: str, payload: LeaveAction, _: dict = Depends(require_roles('admin','hr'))):
    if payload.status not in ['approved','rejected']:
        raise HTTPException(status_code=400, detail="Invalid status")
    db['leave'].update_one({"_id": oid(leave_id)}, {"$set": {"status": payload.status}})
    return {"ok": True}

@app.get('/leave')
def list_leave(_: dict = Depends(require_roles('admin','hr','lead','employee'))):
    return [serialize(x) for x in db['leave'].find({}).sort('created_at', -1)]


# ----------------------- Payroll -----------------------
class PayrollCreate(BaseModel):
    user_id: str
    month: int
    year: int
    basic: float
    allowances: float = 0
    deductions: float = 0

@app.post('/payroll/generate')
def generate_payroll(payload: PayrollCreate, _: dict = Depends(require_roles('admin','hr'))):
    taxable = max(0.0, payload.basic + payload.allowances - payload.deductions)
    net = taxable  # simple for demo
    pay = PayrollSchema(
        user_id=payload.user_id,
        month=payload.month,
        year=payload.year,
        basic=payload.basic,
        allowances=payload.allowances,
        deductions=payload.deductions,
        taxable_amount=taxable,
        net_pay=net,
        payslip_url=None
    )
    pid = create_document('payroll', pay)
    return {"id": pid, "net_pay": net}

@app.get('/payroll')
def list_payroll(user_id: Optional[str] = None, _: dict = Depends(require_roles('admin','hr','employee','lead'))):
    filt = {"user_id": user_id} if user_id else {}
    return [serialize(x) for x in db['payroll'].find(filt).sort('year', -1).sort('month', -1)]


# ----------------------- Projects & Tasks -----------------------
@app.post('/projects')
def create_project(payload: ProjectSchema, user: dict = Depends(require_roles('admin','hr','lead'))):
    pid = create_document('project', payload)
    return {"id": pid}

@app.get('/projects')
def list_projects(_: dict = Depends(require_roles('admin','hr','lead','employee'))):
    return [serialize(x) for x in db['project'].find({}).sort('created_at', -1)]

class TaskCreate(BaseModel):
    project_id: str
    title: str
    description: Optional[str] = None
    assignees: List[str] = []
    priority: str = 'medium'

@app.post('/tasks')
def create_task(payload: TaskCreate, _: dict = Depends(require_roles('admin','hr','lead'))):
    task = TaskSchema(
        project_id=payload.project_id,
        title=payload.title,
        description=payload.description,
        assignees=payload.assignees,
        priority=payload.priority
    )
    tid = create_document('task', task)
    return {"id": tid}

@app.get('/tasks')
def list_tasks(project_id: Optional[str] = None, _: dict = Depends(require_roles('admin','hr','lead','employee'))):
    filt = {"project_id": project_id} if project_id else {}
    return [serialize(x) for x in db['task'].find(filt).sort('created_at', -1)]

@app.put('/tasks/{task_id}')
def update_task(task_id: str, payload: Dict[str, Any], _: dict = Depends(require_roles('admin','hr','lead'))):
    db['task'].update_one({"_id": oid(task_id)}, {"$set": payload})
    return {"ok": True}


# ----------------------- Notifications -----------------------
@app.get('/notifications')
def list_notifications(user: dict = Depends(require_roles('admin','hr','lead','employee'))):
    filt = {"$or": [{"user_id": str(user['_id'])}, {"user_id": None}]}
    return [serialize(x) for x in db['notification'].find(filt).sort('created_at', -1)]

@app.post('/notifications/{nid}/read')
def read_notification(nid: str, user: dict = Depends(require_roles('admin','hr','lead','employee'))):
    db['notification'].update_one({"_id": oid(nid)}, {"$set": {"is_read": True}})
    return {"ok": True}


# ----------------------- Reports -----------------------
@app.get('/reports/summary')
def reports_summary(_: dict = Depends(require_roles('admin','hr','lead'))):
    # Simple aggregates for demo
    by_department = {}
    for e in db['employee'].find({}):
        dep = e.get('department_id') or 'Unassigned'
        by_department[dep] = by_department.get(dep, 0) + 1
    payroll_total = sum(p.get('net_pay', 0) for p in db['payroll'].find({}))
    return {
        "employees_by_department": by_department,
        "payroll_total": payroll_total,
        "attendance_heatmap": [],
        "performance": []
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
