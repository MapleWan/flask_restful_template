from app.api import auth_ns
from flask_restx import fields
from app.api.common.utils import api_response
# 定义API模型
# 用户注册/登录请求模型
user_credentials = auth_ns.model('UserCredentials', {
    'username': fields.String(required=True, description='用户名', example='admin'),
    'password': fields.String(required=True, description='密码', example='admin')
})

# 用户注册/登录响应模型

# 登录成功响应模型
login_response_data = auth_ns.model('LoginResponseData', {
    'access_token': fields.String(description='访问令牌'),
    'refresh_token': fields.String(description='刷新令牌'),
    'exp': fields.Integer(description='令牌过期时间戳(毫秒)')
})

login_response = auth_ns.model('LoginResponse', {
    'success': fields.Boolean(description='操作是否成功'),
    'message': fields.String(description='响应消息'),
    'data': fields.Nested(login_response_data, description='登录响应数据')
})


# 登录响应模型(继承api_response)  不能修改 data 字段
# login_response = auth_ns.inherit('LoginResponse', api_response, {
#     'data': fields.Nested(login_response_data, description='登录响应数据')
# })

# 使用 clone 方法复制 api_response，并修改 data 字段
# login_response = auth_ns.clone('LoginResponse', api_response, {
#     'data': fields.Nested(login_response_data, description='登录响应数据')
# })
# login_response = auth_ns.clone('LoginResponse', api_response)
# login_response['data'] = fields.Nested(login_response_data, description='登录响应数据')