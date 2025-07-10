from datetime import datetime
import uuid

from flask_restful import Resource, reqparse
from flask_jwt_extended import create_access_token, create_refresh_token, decode_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash

from ..schema.register_sha import register_args_valid
from ..models.user import User
from ..common.utils import res

def generate_tokens(id):
    access_token = create_access_token(identity=id)
    refresh_token = create_refresh_token(identity=id)
    return {
        'access_token': 'Bearer ' + access_token,
        'refresh_token': 'Bearer ' + refresh_token
    }

class Login(Resource):
    def post(self):
        """
        用户登录接口
        ---
        tags:
          - 用户相关
        parameters:
          - name: body
            in: body
            required: true
            schema:
              type: object
              required:
                - username
                - password
              properties:
                username:
                  type: string
                  description: 用户名
                password:
                  type: string
                  description: 密码
        responses:
          200:
            description: 登录成功
            schema:
              type: object
              properties:
                code:
                  type: integer
                msg:
                  type: string
                data:
                  type: object
                  properties:
                    access_token:
                      type: string
                    refresh_token:
                      type: string
                    exp:
                      type: integer
          400:
            description: 用户不存在
          401:
            description: 密码错误
          500:
            description: 登录失败
        """
        # 解析请求参数
        parser = reqparse.RequestParser()
        # 请求参数校验
        register_args_valid(parser)
        data = parser.parse_args()
        username = data['username']
        user_tuple = User.findUserByUsername(username)
        if user_tuple:
            try:
                (user, ) = user_tuple
                pwd, salt = user.getPwd().get('pwd'), user.getPwd().get('salt')
                valid = check_password_hash(pwd, '{}{}'.format(salt, data['pwd']))
                if valid:
                    # 生成 token
                    tokens_data = generate_tokens(username)
                    decoded_token = decode_token(tokens_data['access_token'].split(' ')[1]) # 解析过期时间返回给前端
                    return res(data={
                        'access_token': tokens_data['access_token'],
                        'refresh_token': tokens_data['refresh_token'],
                        'exp': decoded_token['exp'] * 1000, # 将时间戳转换为毫秒
                    }, message='success', success=True, code=200)
                else:
                    return res(message='密码错误', success=False, code=401)
            except Exception as e:
                return res(data=None, message='登录失败，{}'.format(e), success=False, code=500)
        else:
            return res(message='用户不存在', success=False, code=400)

    @jwt_required(refresh=True)
    def get(self):
        # access_token 过期后，使用 refresh_token 获取新的 access_token
        # 可以先从 refresh_token 中获取用户名，再生成新的 access_token
        current_username = get_jwt_identity()

        # 在生成新的 token
        access_token = create_access_token(identity=current_username)
        return res(data={'access_token': 'Bearer ' + access_token}, message='获取新的 access_token 成功', success=True, code=200)
