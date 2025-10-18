import os
from datetime import timedelta
from dotenv import load_dotenv


load_dotenv()


class Config:
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret")
SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///zerotrust.db")
SQLALCHEMY_TRACK_MODIFICATIONS = False


JWT_SECRET = os.getenv("JWT_SECRET", "dev-jwt-secret")
ACCESS_TTL = timedelta(minutes=int(os.getenv("ACCESS_MINUTES", 10)))
REFRESH_TTL = timedelta(days=int(os.getenv("REFRESH_DAYS", 14)))
