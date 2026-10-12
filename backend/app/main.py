from contextlib import asynccontextmanager
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

DB = Path(__file__).resolve().parent.parent / "fixnow.db"
SESSION_DAYS = 7


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS mechanics (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, specialty TEXT NOT NULL,
          area TEXT NOT NULL, rating REAL NOT NULL, eta INTEGER NOT NULL,
          available INTEGER NOT NULL DEFAULT 1)""")
        c.execute("""CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('customer','admin')),
          created_at TEXT NOT NULL DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')))""")
        c.execute("""CREATE TABLE IF NOT EXISTS bookings (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT NOT NULL,
          vehicle TEXT NOT NULL, issue TEXT NOT NULL, description TEXT NOT NULL,
          location TEXT NOT NULL, mechanic_id INTEGER, status TEXT NOT NULL,
          eta INTEGER, created_at TEXT NOT NULL DEFAULT (datetime('now')))""")
        cols = {r["name"] for r in c.execute("PRAGMA table_info(bookings)").fetchall()}
        if "user_id" not in cols:
            c.execute("ALTER TABLE bookings ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if c.execute("SELECT COUNT(*) FROM mechanics").fetchone()[0] == 0:
            c.executemany("INSERT INTO mechanics(name,specialty,area,rating,eta,available) VALUES(?,?,?,?,?,?)", [
              ("Ravi Auto Care", "Two-wheeler specialist", "Vijayawada", 4.8, 18, 1),
              ("City Roadside Motors", "Car and battery support", "Vijayawada", 4.7, 25, 1),
              ("QuickWheel Service", "Tyres and punctures", "Vijayawada", 4.6, 22, 1),
              ("Highway Assist Demo", "Car breakdown support", "Guntur", 4.5, 35, 1)])
        c.commit()


@asynccontextmanager
async def lifespan(app):
    init_db()
    yield


app = FastAPI(title="FixNow API", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"], allow_methods=["*"], allow_headers=["*"])


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: EmailStr
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class BookingIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    phone: str = Field(min_length=7, max_length=20)
    vehicle: Literal["Two-wheeler", "Car"]
    issue: Literal["Engine won't start", "Flat tyre", "Battery problem", "Fuel issue", "Breakdown / towing advice", "Other"]
    description: str = Field(min_length=5, max_length=600)
    location: str = Field(min_length=3, max_length=200)


class StatusIn(BaseModel):
    status: Literal["Accepted", "On the way", "Arrived", "In progress", "Completed", "Cancelled"]


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return f"pbkdf2_sha256${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, salt_hex, expected = encoded.split("$", 2)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 310_000).hex()
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def public_user(row):
    return {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"]}


def create_session(user_id: int) -> str:
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    expiry = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    with db() as c:
        c.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (digest, user_id, expiry))
        c.commit()
    return raw


def current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Please log in to continue")
    raw = authorization[7:].strip()
    if not raw or len(raw) > 200:
        raise HTTPException(401, "Invalid or expired session. Please log in again.")
    digest = hashlib.sha256(raw.encode()).hexdigest()
    now = datetime.now(timezone.utc).isoformat()
    with db() as c:
        row = c.execute("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>?""", (digest, now)).fetchone()
    if not row:
        raise HTTPException(401, "Invalid or expired session. Please log in again.")
    return public_user(row)


def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


def mechanics():
    with db() as c:
        return [dict(r) | {"available": bool(r["available"]), "demo": True} for r in c.execute("SELECT * FROM mechanics ORDER BY rating DESC").fetchall()]


def bookings_for(user):
    sql = """SELECT b.*,m.name AS mechanic_name FROM bookings b
      LEFT JOIN mechanics m ON m.id=b.mechanic_id"""
    params = ()
    if user["role"] != "admin":
        sql += " WHERE b.user_id=?"
        params = (user["id"],)
    sql += " ORDER BY b.id DESC"
    with db() as c:
        return [dict(r) for r in c.execute(sql, params).fetchall()]


def get_booking(booking_id: int, user):
    sql = """SELECT b.*,m.name AS mechanic_name FROM bookings b
      LEFT JOIN mechanics m ON m.id=b.mechanic_id WHERE b.id=?"""
    with db() as c:
        row = c.execute(sql, (booking_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Booking not found")
    result = dict(row)
    if user["role"] != "admin" and result.get("user_id") != user["id"]:
        raise HTTPException(404, "Booking not found")
    return result


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "FixNow API"}


@app.post("/api/auth/register", status_code=201)
def register(data: RegisterIn):
    email = str(data.email).strip().lower()
    with db() as c:
        try:
            cur = c.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'customer')",
                            (data.name.strip(), email, hash_password(data.password)))
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "An account with this email already exists")
        row = c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    user = public_user(row)
    return {"token": create_session(user["id"]), "user": user}


@app.post("/api/auth/login")
def login(data: LoginIn):
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (str(data.email).strip(),)).fetchone()
    if not row or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(401, "Incorrect email or password")
    return {"token": create_session(row["id"]), "user": public_user(row)}


@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return user


@app.post("/api/auth/logout")
def logout(authorization: str | None = Header(default=None), user=Depends(current_user)):
    raw = authorization[7:].strip()
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(raw.encode()).hexdigest(),))
        c.commit()
    return {"ok": True}


@app.get("/api/mechanics")
def list_mechanics():
    return mechanics()


@app.get("/api/bookings")
def list_bookings(user=Depends(current_user)):
    return bookings_for(user)


@app.get("/api/bookings/{booking_id}")
def one_booking(booking_id: int, user=Depends(current_user)):
    return get_booking(booking_id, user)


@app.post("/api/bookings", status_code=201)
def create_booking(data: BookingIn, user=Depends(current_user)):
    available = [m for m in mechanics() if m["available"] and (data.vehicle == "Car" or "Two-wheeler" in m["specialty"] or "Tyres" in m["specialty"])]
    location = data.location.lower()
    available.sort(key=lambda m: (0 if location in m["area"].lower() or m["area"].lower() in location else 1, -m["rating"]))
    chosen = available[0] if available else None
    with db() as c:
        cur = c.execute("""INSERT INTO bookings(name,phone,vehicle,issue,description,location,mechanic_id,status,eta,user_id)
          VALUES(?,?,?,?,?,?,?,?,?,?)""", (data.name, data.phone, data.vehicle, data.issue, data.description, data.location,
          chosen["id"] if chosen else None, "Requested" if chosen else "Searching", chosen["eta"] if chosen else None, user["id"]))
        booking_id = cur.lastrowid
        c.commit()
    return get_booking(booking_id, user)


@app.patch("/api/bookings/{booking_id}/status")
def update_status(booking_id: int, data: StatusIn, user=Depends(require_admin)):
    with db() as c:
        if not c.execute("SELECT id FROM bookings WHERE id=?", (booking_id,)).fetchone():
            raise HTTPException(404, "Booking not found")
        c.execute("UPDATE bookings SET status=? WHERE id=?", (data.status, booking_id))
        c.commit()
    return get_booking(booking_id, user)


@app.post("/api/bookings/{booking_id}/cancel")
def cancel_booking(booking_id: int, user=Depends(current_user)):
    b = get_booking(booking_id, user)
    if user["role"] != "admin" and b["status"] not in ("Requested", "Searching"):
        raise HTTPException(409, "This booking can no longer be cancelled by the customer")
    if b["status"] in ("Completed", "Cancelled"):
        raise HTTPException(409, "This booking is already closed")
    with db() as c:
        c.execute("UPDATE bookings SET status='Cancelled' WHERE id=?", (booking_id,))
        c.commit()
    return get_booking(booking_id, user)


@app.post("/api/bookings/{booking_id}/assign/{mechanic_id}")
def assign(booking_id: int, mechanic_id: int, user=Depends(require_admin)):
    m = next((m for m in mechanics() if m["id"] == mechanic_id and m["available"]), None)
    if not m:
        raise HTTPException(404, "Available sample mechanic not found")
    with db() as c:
        if not c.execute("SELECT id FROM bookings WHERE id=?", (booking_id,)).fetchone():
            raise HTTPException(404, "Booking not found")
        c.execute("UPDATE bookings SET mechanic_id=?,eta=?,status='Requested' WHERE id=?", (mechanic_id, m["eta"], booking_id))
        c.commit()
    return get_booking(booking_id, user)


@app.get("/api/admin/summary")
def summary(user=Depends(require_admin)):
    bs = bookings_for(user)
    return {"total": len(bs), "active": sum(b["status"] not in ("Completed", "Cancelled") for b in bs),
            "completed": sum(b["status"] == "Completed" for b in bs), "mechanics": len(mechanics()), "bookings": bs}
