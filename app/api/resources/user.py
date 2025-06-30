from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models.user import User
from ..common.utils import res

class UserService(Resource):
    @jwt_required()
    def get(self):
        userList = User.findAllUser()
        result = [user.dict() for user in userList]
        return res(data=result, message='success', success=True, code=200)