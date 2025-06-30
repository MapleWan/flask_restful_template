# 公共 response 方法
def res(data=None, message='Ok', success=True, code=200):
    return {
        'success': success,
        'message': message,
        'data': data,
    }, code

def format_datetime_to_json(datetime, format_str='%Y-%m-%d %H:%M:%S'):
    return datetime.strftime(format_str)