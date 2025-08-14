from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import re

app = FastAPI()

USERS_FILE = "users.txt"
SEPARATOR = "|"
SESSIONS_FILE = "sessions.txt"

class User(BaseModel):
    username: str
    password: str


def save_user(username: str, password: str):
    with open(USERS_FILE, "a") as f:
        f.write(f"{username}{SEPARATOR}{password}\n")


def get_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        lines = f.readlines()
    users = {}
    for line in lines:
        if SEPARATOR in line:
            user, pwd = line.strip().split(SEPARATOR)
            users[user] = pwd
    return users


def validate_password(password: str):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Za-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[^A-Za-z0-9]", password):
        return False
    return True


def save_session(username: str):
    """Add a username to sessions file."""
    sessions = get_sessions()
    if username not in sessions:
        with open(SESSIONS_FILE, "a") as f:
            f.write(f"{username}\n")


def remove_session(username: str):
    """Remove a username from sessions file."""
    sessions = get_sessions()
    if username in sessions:
        sessions.remove(username)
        with open(SESSIONS_FILE, "w") as f:
            for user in sessions:
                f.write(f"{user}\n")


def get_sessions():
    """Get list of logged-in usernames."""
    if not os.path.exists(SESSIONS_FILE):
        return []
    with open(SESSIONS_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]


@app.post("/register")
def register(user: User):
    users = get_users()

    if user.username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    if not validate_password(user.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters long and include a letter, number, and symbol."
        )

    save_user(user.username, user.password)
    return {"message": "User registered successfully"}


@app.post("/login")
def login(user: User):
    users = get_users()
    if user.username not in users or users[user.username] != user.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    save_session(user.username)
    return {"message": "Login successful", "logged_in_users": get_sessions()}


@app.post("/logout")
def logout(user: User):
    sessions = get_sessions()
    if user.username not in sessions:
        raise HTTPException(status_code=400, detail="User not logged in")

    remove_session(user.username)
    return {"message": "Logout successful", "logged_in_users": get_sessions()}
