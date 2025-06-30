from flask import Blueprint
from flask_restful import Api
from .resources.register import Register
from .resources.login import Login
from .resources.logout import Logout
from .resources.user import UserService

api_blueprint = Blueprint('api', __name__, url_prefix='/api')
api = Api(api_blueprint)

api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
# api.add_resource(Login, '/login', '/refresh', '/test')  # 可以添加多个路由

api.add_resource(Logout, '/logout')
api.add_resource(UserService, '/user')