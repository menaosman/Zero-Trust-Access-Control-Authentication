from flask import Flask, render_template
from config import Config
from database import db
from blueprints.auth import bp as auth_bp
from blueprints.attest import bp as attest_bp
from blueprints.resources import bp as res_bp
from blueprints.admin import bp as admin_bp




def create_app():
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)


app.register_blueprint(auth_bp)
app.register_blueprint(attest_bp)
app.register_blueprint(res_bp)
app.register_blueprint(admin_bp)


@app.get("/")
def home():
return render_template("login.html")


@app.get("/dashboard")
def dashboard():
return render_template("dashboard.html")


return app




def init_db():
app = create_app()
with app.app_context():
from models import User, Device, Token, Audit
db.create_all()
print("DB initialized")


if __name__ == "__main__":
app = create_app()
app.run(debug=True)
