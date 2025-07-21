import uuid

from flask_restx import Resource, reqparse
from werkzeug.security import generate_password_hash
from app.api import auth_ns
from .auth_api_model import user_credentials
from app.api.models.user import User
from app.api.common.utils import res
from app.api.schema.register_sha import register_args_valid

class Register(Resource):
    @auth_ns.expect(user_credentials)
    @auth_ns.doc(description='用户注册接口',
             responses={
                 201: '注册成功',
                 400: '用户名已存在',
                 500: '服务器内部错误'
             })
    def post(self):
        parser = reqparse.RequestParser()
        # parser.add_argument('username', type=str, location='json')
        # parser.add_argument('password', type=str, dest='pwd', location='json')
        register_args_valid(parser)
        data = parser.parse_args()
        if User.findUserByUsername(data['username']):
            # return {'success': False, 'message': '用户名已存在', 'data': None }, 400
            return res(message='用户名已存在', success=False, code=400)
        else:
            try:
                data['salt'] = uuid.uuid4().hex
                data['pwd'] = generate_password_hash('{}{}'.format(data['salt'], data['pwd']))
                user = User(**data)
                user.addUser()
                # return {'success': True, 'message': '注册成功', 'data': user.dict()}, 201
                return res(data=user.dict(), message='注册成功', success=True, code=201)
            except Exception as e:
                # return {'success': False, 'message': '注册失败，{}'.format(e), 'data': None}, 500
                return res(message='注册失败，{}'.format(e), success=False, code=500)