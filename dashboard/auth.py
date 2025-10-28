# dashboard/auth.py
"""
Handles authentication for the dashboard using Flask-Login.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

# Simple user store (replace with DB later)
USERS = {
    "admin": generate_password_hash("admin123"),  # username: admin / password: admin123
}

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"

bp = Blueprint("auth", __name__, template_folder="templates")


class User(UserMixin):
    def __init__(self, username):
        self.id = username


@login_manager.user_loader
def load_user(username):
    if username in USERS:
        return User(username)
    return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username in USERS and check_password_hash(USERS[username], password):
            login_user(User(username))
            return redirect(url_for("dashboard.index"))
        flash("Invalid username or password", "error")
    return render_template("login.html")


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
