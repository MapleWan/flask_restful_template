from flask_restx import fields
from app.api import api
# 通用的 api 返回 data 结构
api_response = api.model('ApiResponse', {
    'success': fields.Boolean(description='操作是否成功'),
    'message': fields.String(description='响应消息'),
    # 'data': fields.Raw(description='响应数据'),
    # 'code': fields.Integer(description='响应状态码')
})

# 公共 response 方法
def res(data=None, message='Ok', success=True, code=200):
    return {
        'success': success,
        'message': message,
        'data': data,
    }, code

def format_datetime_to_json(datetime, format_str='%Y-%m-%d %H:%M:%S'):
    return datetime.strftime(format_str)