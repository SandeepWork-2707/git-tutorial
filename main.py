import os, smtplib, secrets
from datetime import datetime, timedelta
from email.message import EmailMessage
from fastapi import FastAPI, Depends, Form, Request, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import Column, Integer, String, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- CONFIGURATION (EDIT THESE) ---
SMTP_EMAIL = "your-email@gmail.com"
SMTP_PASSWORD = "your-app-password" # Get from Google Security -> App Passwords
SECRET_KEY = "PRO_SECRET_99"
ALGORITHM = "HS256"
DATABASE_URL = "sqlite+aiosqlite:///./pro_data.db"

# --- DB & SECURITY SETUP ---
Base = declarative_base()
engine = create_async_engine(DATABASE_URL)
async_session = async_sessionmaker(engine, expire_on_commit=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

# --- UTILS ---
def get_token(email: str):
    expire = datetime.utcnow() + timedelta(hours=1)
    return jwt.encode({"sub": email, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

async def get_db():
    async with async_session() as session: yield session

def send_reset_email(target_email: str, new_pass: str):
    msg = EmailMessage()
    msg.set_content(f"Your temporary password is: {new_pass}\nPlease login and change it.")
    msg['Subject'] = 'Password Reset'
    msg['From'] = SMTP_EMAIL
    msg['To'] = target_email
    with smtplib.SMTP_SSL('://gmail.com', 465) as smtp:
        smtp.login(SMTP_EMAIL, SMTP_PASSWORD)
        smtp.send_message(msg)

# --- UI TEMPLATE GENERATOR ---
def render_page(title: str, form_html: str, script: str = ""):
    return f"""
    <!DOCTYPE html><html lang="en"><head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; font-family: 'Segoe UI', sans-serif; }}
        body {{ height: 100vh; display: flex; justify-content: center; align-items: center; background: linear-gradient(135deg, #667eea, #764ba2); }}
        .container {{ background: #fff; padding: 40px; width: 350px; border-radius: 15px; box-shadow: 0 15px 30px rgba(0,0,0,0.2); text-align: center; }}
        .input-group {{ position: relative; margin-bottom: 25px; }}
        .input-group input {{ width: 100%; padding: 12px 10px; border: 1px solid #ccc; border-radius: 8px; outline: none; }}
        .input-group label {{ position: absolute; top: 50%; left: 10px; transform: translateY(-50%); background: #fff; padding: 0 5px; color: #aaa; transition: 0.3s; pointer-events: none; }}
        .input-group input:focus + label, .input-group input:valid + label {{ top: -8px; font-size: 12px; color: #667eea; }}
        .btn {{ width: 100%; padding: 12px; border: none; border-radius: 8px; background: #667eea; color: #fff; cursor: pointer; }}
        .extra {{ margin-top: 15px; font-size: 14px; }} .extra a {{ color: #667eea; text-decoration: none; }}
        .msg {{ font-size: 12px; margin-bottom: 10px; color: #d9534f; }}
    </style></head>
    <body><div class="container"><h2>{title}</h2>{form_html}</div>{script}</body></html>
    """

# --- APP ---
app = FastAPI()

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn: await conn.run_sync(Base.metadata.create_all)

@app.get("/register", response_class=HTMLResponse)
async def reg_ui():
    return render_page("Sign Up", """
        <form method="post"><div class="input-group"><input type="email" name="email" required><label>Email</label></div>
        <div class="input-group"><input type="password" name="password" required><label>Password</label></div>
        <button type="submit" class="btn">Register</button></form>
        <div class="extra"><p>Already have an account? <a href="/login">Login</a></p></div>
    """)

@app.post("/register")
async def register(email: str = Form(...), password: str = Form(...), db: AsyncSession = Depends(get_db)):
    hashed = pwd_context.hash(password)
    db.add(User(email=email, password=hashed))
    await db.commit()
    return RedirectResponse("/login", status_code=302)

@app.get("/login", response_class=HTMLResponse)
async def login_ui(error: str = None):
    err_div = f'<div class="msg">{error}</div>' if error else ""
    return render_page("Login", f"""
        {err_div}
        <form method="post"><div class="input-group"><input type="email" name="email" required><label>Email</label></div>
        <div class="input-group"><input type="password" name="password" required><label>Password</label></div>
        <button type="submit" class="btn">Login</button></form>
        <div class="extra"><p><a href="/forgot">Forgot Password?</a></p><p><a href="/register">Sign Up</a></p></div>
    """)

@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...), db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.email == email))
    user = res.scalars().first()
    if not user or not pwd_context.verify(password, user.password):
        return RedirectResponse("/login?error=Invalid Credentials", status_code=302)
    
    resp = RedirectResponse("/dashboard", status_code=302)
    resp.set_cookie("access_token", get_token(email), httponly=True)
    return resp

@app.get("/forgot", response_class=HTMLResponse)
async def forgot_ui(msg: str = None):
    m_div = f'<div class="msg" style="color:green">{msg}</div>' if msg else ""
    return render_page("Forgot Password", f"""
        {m_div}
        <form method="post"><div class="input-group"><input type="email" name="email" required><label>Email</label></div>
        <button type="submit" class="btn">Send New Password</button></form>
        <div class="extra"><a href="/login">Back to Login</a></div>
    """)

@app.post("/forgot")
async def forgot_pass(email: str = Form(...), db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(User).where(User.email == email))
    user = res.scalars().first()
    if user:
        temp_pass = secrets.token_hex(4)
        user.password = pwd_context.hash(temp_pass)
        await db.commit()
        try:
            send_reset_email(email, temp_pass)
            return RedirectResponse("/forgot?msg=Email Sent!", status_code=302)
        except:
            return RedirectResponse("/forgot?msg=SMTP Error", status_code=302)
    return RedirectResponse("/forgot?msg=User not found", status_code=302)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    token = request.cookies.get("access_token")
    if not token: return RedirectResponse("/login")
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return render_page("Dashboard", f"<h3>Welcome</h3><p>{payload['sub']}</p><br><a href='/logout'>Logout</a>")

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login")
    resp.delete_cookie("access_token")
    return resp

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
