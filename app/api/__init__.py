from flask import Blueprint
from flask_restx import Api, Namespace

# 创建API蓝图
api_blueprint = Blueprint('api', __name__, url_prefix='/api')

# 创建Flask-RESTX的Api实例
api = Api(
    api_blueprint,
    version='1.0',
    title='Flask RESTful API',
    description='基于Flask-RESTX的RESTful API',
    doc='/docs/',  # Swagger文档路径
    authorizations={
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'JWT Token格式: Bearer <token>'
        }
    },
    security='Bearer'
)

auth_ns = Namespace('auth', description='认证相关接口', path='/auth')
users_ns = Namespace('users', description='用户管理接口', path='/users')

from app.api.resources.auth.login import Login
from app.api.resources.auth.logout import Logout
from app.api.resources.auth.register import Register
from app.api.resources.user.user import UserService

auth_ns.add_resource(Register, '/register')
auth_ns.add_resource(Login, '/login')
auth_ns.add_resource(Logout, '/logout')

users_ns.add_resource(UserService, '/profile')
# 注册命名空间到API
api.add_namespace(auth_ns)
api.add_namespace(users_ns)
