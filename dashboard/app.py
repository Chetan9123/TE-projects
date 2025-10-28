# dashboard/app.py
from flask import Flask
from flask_login import login_required
from dashboard.routes import register_routes
from dashboard.auth import bp as auth_bp, login_manager

def create_app(config: dict = None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = "super_secret_key_change_this"  # ⚠️ Replace for production
    if config:
        app.config.update(config)

    # Initialize login manager
    login_manager.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    register_routes(app)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8501, debug=True)
