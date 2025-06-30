import os
from datetime import timedelta
# 环境变量读取本地 .env 文件

# 数据库相关配置
# 用户名
USERNAME = os.getenv('MYSQL_USER_NAME')
# 密码
PASSWORD = os.getenv("MYSQL_USER_PASSWORD")
# 主机
HOSTNAME = os.getenv("MYSQL_HOSTNAME")
# 端口
PORT = os.getenv("MYSQL_PORT")
# 数据库
DATABASE = os.getenv("MYSQL_DATABASE_NAME")

# 数据库连接相关
DIALECT = "mysql"
DRIVER = "pymysql"

class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = f"{DIALECT}+{DRIVER}://{USERNAME}:{PASSWORD}@{HOSTNAME}:{PORT}/{DATABASE}"
    SQLALCHEMY_ECHO = False

    # JWT 相关配置
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") # 密钥
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1) # 1小时
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30) # 30天
    JWT_BLOCKLIST_TOKEN_CHECKS = ['access'] # 检查类型

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = ""

class TestingConfig(Config):
    DEBUG = True
    TESTING = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}