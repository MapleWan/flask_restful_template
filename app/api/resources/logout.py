from flask_restful import Resource
from flask_jwt_extended import jwt_required, get_jwt
from ..models.revoked_token import RevokedToken
from ..common.utils import res

class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        try:    
            revoked_token = RevokedToken(jti=jti)
            revoked_token.add()
            return res(data=None, message='退出成功', success=True, code=200)
        except Exception as e:
            return res(data=None, message='服务器繁忙', success=False, code=500)