"""
EMS Database Schemas

Each Pydantic model corresponds to a MongoDB collection (lowercase of class name).
These are used for validation on create/update operations.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import date, datetime


# Auth / Users
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="Salted password hash")
    role: Literal['admin', 'hr', 'lead', 'employee'] = Field('employee', description="User role")
    is_active: bool = Field(True, description="Active status")
    avatar_url: Optional[str] = Field(None, description="Profile photo URL")
    last_login_at: Optional[datetime] = None

class Session(BaseModel):
    user_id: str
    token: str
    expires_at: datetime
    user_agent: Optional[str] = None
    ip: Optional[str] = None


# Organization
class Department(BaseModel):
    name: str
    description: Optional[str] = None
    lead_user_id: Optional[str] = None

class Employee(BaseModel):
    user_id: str
    employee_code: str
    phone: Optional[str] = None
    address: Optional[str] = None
    designation: Optional[str] = None
    department_id: Optional[str] = None
    date_of_joining: Optional[date] = None
    salary: float = 0
    status: Literal['active', 'on_leave', 'resigned'] = 'active'
    documents: List[str] = []  # file ids/urls
    work_history: List[str] = []


# Attendance & Leave
class Attendance(BaseModel):
    user_id: str
    date: date
    clock_in: Optional[datetime] = None
    clock_out: Optional[datetime] = None
    notes: Optional[str] = None

class Leave(BaseModel):
    user_id: str
    start_date: date
    end_date: date
    reason: Optional[str] = None
    status: Literal['pending','approved','rejected'] = 'pending'
    approver_id: Optional[str] = None


# Payroll
class Payroll(BaseModel):
    user_id: str
    month: int  # 1-12
    year: int
    basic: float
    allowances: float = 0
    deductions: float = 0
    taxable_amount: float = 0
    net_pay: float = 0
    payslip_url: Optional[str] = None


# Projects & Tasks
class Project(BaseModel):
    name: str
    description: Optional[str] = None
    owner_id: str
    members: List[str] = []
    status: Literal['planned','active','on_hold','completed'] = 'planned'

class Task(BaseModel):
    project_id: str
    title: str
    description: Optional[str] = None
    assignees: List[str] = []
    priority: Literal['low','medium','high','urgent'] = 'medium'
    status: Literal['todo','in_progress','review','done'] = 'todo'
    due_date: Optional[date] = None


# Notifications
class Notification(BaseModel):
    user_id: str
    type: Literal['leave','task','system'] = 'system'
    title: str
    message: str
    is_read: bool = False


# Files (metadata only)
class Document(BaseModel):
    user_id: str
    name: str
    url: str
    category: Optional[str] = None
