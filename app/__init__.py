# from flask import Flask
# from flask_restful import Resource, Api

# app = Flask(__name__)
# api = Api(app)

# class Hello(Resource):
#     def get(self):
#         return {'message': 'test'}

# api.add_resource(Hello, '/hello')

import os
from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from .config import config
from .api.models import db
from .api.models.revoked_token import RevokedToken
from .api.models.user import User
from .api import api_blueprint
from .manage import migrate
from flasgger import Swagger

def create_app(config_name):
    #初始化Flask项目
    app = Flask(__name__)
    # 加载配置
    app.config.from_object(config[config_name])
    # 初始化数据库
    db.init_app(app) # init_app 会去读取 app.config 中相关的数据库连接配置，连接数据库
    # 初始化迁移
    migrate.init_app(app, db)
    # 注册蓝图
    app.register_blueprint(api_blueprint)

    # 初始化Swagger
    swagger = Swagger(app)
    # 初始化 JWT
    jwt = JWTManager(app)
    register_JWT_hooks(jwt)
    
    # 解决跨域
    CORS(app)
    return app

def register_JWT_hooks(jwt):
    # 注册JWT钩子函数，用于检查token是否在黑名单中
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        return RevokedToken.is_jti_blacklisted(jti)

# 创建app实例
app = create_app(os.getenv('FLASK_ENV', 'development'))