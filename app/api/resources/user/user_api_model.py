from flask_restx import fields
from app.api import users_ns
from app.api.common.utils import api_response
# 用户信息模型
user_info = users_ns.model('UserInfo', {
    'id': fields.Integer(description='用户ID'),
    'username': fields.String(description='用户名'),
    'created_at': fields.String(description='创建时间'),
    'updated_at': fields.String(description='更新时间')
})

# user_list_response = users_ns.model('UserListResponse', {
#     'success': fields.Boolean(description='操作是否成功'),
#     'message': fields.String(description='响应消息'),
#     'data': fields.List(fields.Nested(user_info), description='用户列表')
# })

user_list_response = users_ns.inherit('UserListResponse', api_response, {
    'data': fields.List(fields.Nested(user_info), description='用户列表')
})