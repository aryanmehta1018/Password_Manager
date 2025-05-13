import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'abcdefg')
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:pass@localhost/password_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

