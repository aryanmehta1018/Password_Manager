import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'abcdefg')
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:ronaldorox@localhost/password_manager'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

