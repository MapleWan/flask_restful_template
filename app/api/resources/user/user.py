from flask_restx import Resource, marshal_with
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.api.models.user import User
from app.api import users_ns
from .user_api_model import user_list_response


class UserService(Resource):
    @jwt_required()
    @users_ns.doc(description='获取所有用户信息',
             responses={
                 200: '成功获取用户列表',
                 401: '未授权访问',
                 500: '服务器内部错误'
             })
    @users_ns.marshal_with(user_list_response)
    def get(self):
        user_list = User.findAllUser()
        result = [user.dict() for user in user_list]
        # return res(data=result, message='success', success=True, code=200)
        return {
            'success': True,
            'message': 'success',
            'data': result
        }, 200