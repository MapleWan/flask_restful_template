使用 python Flask 搭建具有登录注册功能的Restful API 基本后端代码模板。

[参考](https://juejin.cn/post/7252976055093592120#heading-7)

# 项目初始化

- 使用 Flask + Flask RESTful 搭建 API 应用并使用 Blueprint(蓝图) 管理 API；
- 使用 [Flask-SQLAlchemy](https://flask-sqlalchemy.palletsprojects.com/en/stable/quickstart/) 扩展实现 ORM 操作 MySQL 数据库；
- 基于 JWT 验证实现注册、登录以及登出接口；
- 实现一个最基本的列表获取接口；
- 解决跨域问题；
- 使用 Docker 部署该应用。


## 环境创建

**注意：** 以下所有操作与命令都在 Macos 环境下进行，Windows 或 Linux 可能有些许不同

使用 `Anaconda` 环境，可以用清华源下载

```
conda create -n py312 python=3.12.11
```

或者使用虚拟环境
```
python -m venv .venv  # 项目目录中会多一个 .venv 的虚拟环境目录
. .venv/bin/activate  # 激活虚拟环境
```

## 依赖安装

```
pip install Flask flask-restful python-dotenv
```

## hello-world 接口实现

```python
# app/__init__.py
from flask import Flask
from flask_restful import Resource, Api
app = Flask(__name__)
# app = Flask('wzf')
api = Api(app)

class Hello(Resource):
    def get(self):
        return {'message': 'test'}

api.add_resource(Hello, '/hello')
```

使用 `Flask()` 初始化一个 Flask 应用实例赋值给 `app`，传入的 `__name__` 则是模块名 `"app"`。我们这里也可以传入一个固定字符串，但是一般情况下不会这么使用。


再使用 `Api(app)` 初始化一个 flask_restful 实例赋值给 `api`。 接下来我们定义了 `Hello` 这个类，它继承于 `Resource` 类。这个类中定义一个名为 `get` 的函数，它返回一个固定的 JSON 为`{'message': 'test'}`。

最后我们使用 `api.add_resource(HelloWorld, '/hello')` 去注册接口，并指定了访问路由，当访问的接口路径为 `"/hello"` 且请求方式为 `GET` 时，就会调用该类中定义好的 `get()` 函数处理。在以 `Resource` 类为基类的派生类中，就是我们定义不同 HTTP 请求方式的地方，所以在这个类中，你还可以定义 `post`，`put`，`delete` 等函数。


## 运行

```python
# run.py
from app import app
if __name__ == '__main__':
app.run(host='0.0.0.0', port=10630, debug=True)
```

`host='0.0.0.0'`
- 作用：指定服务器监听的网络接口
- `0.0.0.0`：监听所有网络接口（包括外部访问）
- `127.0.0.1`：只监听本地回环接口（仅本机访问）
- 实际效果：允许从其他设备访问你的应用

`port=10630`
- 作用：指定服务器监听的端口号
- 默认值：通常是 `5000`
- 自定义端口：`10630`
- 访问地址：`http://localhost:10630` 或 `http://你的IP:10630`

`debug=True`
- 作用：启用调试模式
- 功能：
	- 代码修改后自动重启服务器
	- 显示详细的错误信息
	- 提供交互式调试器
- 注意：生产环境应该设置为 `False`

### 启动方式1

直接运行
```shell
python run.py
```

### 启动方式2

在项目目录下新建 `.env`文件，设置一些环境变量，这些环境变量的命名方式都是 Flask 规定的，这样指定环境变量的好处就是我们可以通过控制台执行 `flask run` 命令来启动服务。 需要注意的是，如果你通过 `flask run` 命令来启动服务，那么 Flask 的配置会默认以环境变量为准，并且会忽略 `run.py` 中的配置项。

```
# 当前环境
FLASK_ENV=development
# 是否开启调试模式
FLASK_DEBUG=True
# 项目入口文件
FLASK_APP=run.py
# 运行地址
FLASK_RUN_HOST=0.0.0.0
# 运行端口
FLASK_RUN_PORT=5003

# 应用密钥
SECRET_KEY=your-secret-key-change-in-production
```

```shell
flask run
```

## 测试

可以通过浏览器或者postman 等工具访问 `http://127.0.0.1:5003/hello`来测试是否返回了`{"message": "test"}`JSON 字符串


# 目录结构优化

对于代码
```python
# app/__init__.py
from flask import Flask
from flask_restful import Resource, Api
app = Flask(__name__)
# app = Flask('wzf')
api = Api(app)

class Hello(Resource):
    def get(self):
        return {'message': 'test'}

api.add_resource(Hello, '/hello')
```

可以发现，`api`、`Resource`等的管理都在一个文件中进行，如果我们需要引入数据库连接等功能或者新增很多其他的业务功能，这种显然是不合理的。因此，按照以下的项目目录结构来组织代码，增强项目的可扩展性

```bash
/
├── .venv/
├── app/
│   └── api/ # api 接口模块
│       └── __init__.py # 注册以及生成蓝图
│       └── common/ # 公共方法
│       └── models/ # 模型，与数据库相关
│       └── resources/ # 接口
│       └── schema/ # 校验
│   └── __init__.py # 整个应用的初始化
│   └── config.py # 配置项
│   └── manage.py # 数据库迁移工具管理
├── .env # 环境变量
├── run.py # 入口文件
```

# mysql数据库连接

## 环境准备

### python 相关库安装
`pip install Flask-SQLAlchemy Flask-Migrate pymysql`

### MySQL环境安装

我这里使用了 docker 环境来安装，当然，直接在 MySQL 官网下载对应的安装包也可以

1. 先拉取 MySQL 镜像
```
docker pull --platform linux/arm64 mysql:8.4.5 # --platform linux/arm64 指定 arm 版本安装 x86平台安装时可以删除
```

2. 使用 MySQL 镜像新建容器（虚拟机）
```shell
docker run -p 3306:3306 --name  sample-mysql -e MYSQL_ROOT_PASSWORD=123456 -d mysql:8.4.5

# 把MySQL的存储data文件、存储配置文件挂载出来，所以用以下更全的会相对好一些，这样重启容器也不会造成丢失数据
docker run -p 3306:3306 --name  sample-mysql -e MYSQL_ROOT_PASSWORD=123456 -v /Users/maplewan/docker-data/sample-mysql/log:/var/log/mysql -v /Users/maplewan/docker-data/sample-mysql/data:/var/lib/mysql -v /Users/maplewan/docker-data/sample-mysql/conf:/etc/mysql -d mysql:8.4.5
# 把宿主机目录 /Users/maplewan/docker-data/sample-mysql/conf 全量挂载到了容器的 /etc/mysql，但这个目录里缺少了 MySQL 启动时会自动查找的子目录 /etc/mysql/conf.d（和 /etc/mysql/mysql.conf.d）。因此在执行 includedir 指令时找不到路径，就报错退出
mkdir -p /Users/maplewan/docker-data/sample-mysql/conf/conf.d
mkdir -p /Users/maplewan/docker-data/sample-mysql/conf/mysql.conf.d
```

3. 连接测试
可以使用 DBeaver 软件来连接测试

可能会出现`Public Key Retrieval is not allowed  MySQL`的问题

通常出现在使用 MySQL 8+ 数据库时，客户端尝试通过用户名密码连接，但使用了 caching_sha2_password 认证插件，而 JDBC 连接配置中没有允许公钥检索。

可以在 `JDBC_URL`中添加参数`allowPublicKeyRetrieval=true&useSSL=false`
如：`jdbc:mysql://localhost:3306/your_db?allowPublicKeyRetrieval=true&useSSL=false`


# 使用数据库实现注册功能

## 1. 更新`.env`文件相关变量

```
# .env

# 当前环境
FLASK_ENV=development
# 是否开启调试模式
FLASK_DEBUG=True
# 项目入口文件
FLASK_APP=run.py
# 运行地址
FLASK_RUN_HOST=127.0.0.1
# 运行端口
FLASK_RUN_PORT=5003

# 应用密钥
SECRET_KEY=7b4bd29d8001569cd6a72aa335c84419286fcdcaa1d075131ba3adac41cef4cb

# 数据库配置相关
MYSQL_USER_NAME=root
MYSQL_USER_PASSWORD=123456
MYSQL_HOSTNAME=127.0.0.1
MYSQL_PORT=3307
MYSQL_DATABASE_NAME=sample
```

## 2. 创建config类管理配置

```python
# app/cnfig.py

import os

# 环境变量读取本地 .env 文件

# 数据库相关配置
# 用户名
USERNAME = os.getenv('MYSQL_USER_NAME')
# 密码
PASSWORD = os.getenv("MYSQL_USER_PASSWORD")
# 主机
HOSTNAME = os.getenv("MYSQL_HOSTNAME")
# 端口
PORT = os.getenv("MYSQL_PORT")
# 数据库
DATABASE = os.getenv("MYSQL_DATABASE_NAME")

# 数据库连接相关
DIALECT = "mysql"
DRIVER = "pymysql"

class Config(object):
    DEBUG = False
    TESTING = False
    SECRET_KEY = os.getenv("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = f"{DIALECT}+{DRIVER}://{USERNAME}:{PASSWORD}@{HOSTNAME}:{PORT}/{DATABASE}"
    print(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_ECHO = False

class DevelopmentConfig(Config):
    DEBUG = True

class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = ""

class TestingConfig(Config):
    DEBUG = True
    TESTING = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
```

## 3. 初始化数据库连接与数据库迁移工具

```python
# app/api/models/__init__.py
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()

# app/manage.py 
from flask_migrate import Migrate
migrate = Migrate()
```
## 4. 创建数据库模型类

```python
# app/api/models/user.py

from . import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'user' # 表名 与 数据库中的表名一一对应
    
    # 主键 id
    id = db.Column(db.Integer(), primary_key=True, nullable=False, autoincrement=True, comment='主键ID')
    # 用户名
    username = db.Column(db.String(40), nullable=False, default='', comment='用户姓名')
    # 密码
    pwd = db.Column(db.String(255), comment='密码')
    # salt
    salt = db.Column(db.String(32), comment='salt')
    # 创建时间
    created_at = db.Column(db.DateTime(), nullable=False, default=datetime.now, comment='创建时间')
    # 更新时间
    updated_at = db.Column(db.DateTime(), nullable=False, default=datetime.now, onupdate=datetime.now, comment='更新时间')

    # 新增用户
    def addUser(self):
        db.session.add(self)
        db.session.commit()

    # 用户信息
    def dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'pwd': self.pwd,
            'salt': self.salt,
            # 'created_at': self.created_at.isoformat() if self.created_at else None,
            # 'updated_at': self.updated_at.isoformat() if self.updated_at else None
            'created_at': format_datetime_to_json(self.created_at),
            'updated_at': format_datetime_to_json(self.updated_at)
        }
    
    # 获取密码和salt
    def getPwd(self):
        return {
            'pwd': self.pwd,
            'salt': self.salt
        }
    
    # 按 username 查询用户
    @classmethod
    def findUserByUsername(cls, username):
        return db.session.execute(db.select(cls).filter_by(username=username)).first()
    
    # 返回所有用户
    @classmethod
    def findAllUser(cls):
        return db.session.query(cls).all()
```

## 5. 使用蓝图，用于接口分模块管理

**创建一些公共的 utils 和入参校验方法**

```python
# app/api/common/utils.py
# 公共 response 方法
def res(data=None, message='Ok', success=True, code=200):
    return {
        'success': success,
        'message': message,
        'data': data,
    }, code
# 格式化时间，不然时间转 json 格式的时候会报错
def format_datetime_to_json(datetime, format_str='%Y-%m-%d %H:%M:%S'):
	return datetime.strftime(format_str)


# app/api/schema/register_sha.py
def register_args_valid(parser):
    parser.add_argument('username', type=str, location='json')
    parser.add_argument('password', type=str, dest='pwd', location='json')
```


### 1. 创建注册服务接口
```python
# app/api/resources/register.py
import uuid

from flask_restful import Resource, reqparse
from werkzeug.security import generate_password_hash

from ..models.user import User
from ..common.utils import res
from ..schema.register_sha import register_args_valid

class Register(Resource):
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
```

### 2. 蓝图初始化与相关Resource添加

在实际开发中，我们会将业务接口拆分模块，比如 `/api/xxx`，所以现在我们需要创建一个 `api` 蓝图来统一管理，在 `/app/api/__init__.py` 文件中写入以下代码：

```python
# app/api/__init__.py

from flask import Blueprint
from flask_restful import Api
from .resources.register import Register

api_blueprint = Blueprint('api', __name__, url_prefix='/api')
api = Api(api_blueprint)

api.add_resource(Register, '/register')
```

## 6. 创建 Flask 对象并初始化相关对象

```python
# app/__init__.py

# from flask import Flask
# from flask_restful import Resource, Api
# app = Flask(__name__)
# api = Api(app)
# class Hello(Resource):
#     def get(self):
#         return {'message': 'test'}
# api.add_resource(Hello, '/hello')

import os
from flask import Flask
from .config import config
from .api.models import db
from .api import api_blueprint
from .manage import migrate

def create_app(config_name):
    # 初始化Flask项目
    app = Flask(__name__)
    # 加载配置
    app.config.from_object(config[config_name])
    # 初始化数据库
    db.init_app(app)  # init_app 会去读取 app.config 中相关的数据库连接配置，连接数据库
    # 初始化迁移
    migrate.init_app(app, db)
    # 注册蓝图
    app.register_blueprint(api_blueprint)
    return app

# 创建app实例
app = create_app(os.getenv('FLASK_ENV', 'development'))
```

## 7. 初始化（创建/更新）数据库表

```shell
# 第一次初始化时使用（会在项目目录下创建一个 migrations 文件夹
flask db init 

# 后面每次修改数据库字段（修改app/api/models中相关文件时）时使用，只需要写 app/api/models 下的相关的模型类，通过以下的命令可以生成对应的表（关于联表相关还未涉及，后续补充）
flask db migrate -m '相关信息'
flask db upgrade

# flask db migrate命令可能会报错 ERROR [flask_migrate] Error: 'cryptography' package is required for sha256_password or caching_sha2_password auth methods，可以通过命令安装以下库解决
pip install cryptography
```

## 8. 测试接口

运行
```shell
flask run
```

如果已经运行，flask 在开发环境下有热更新机制，会自动部署，则不需要执行以上代码

可以使用 postman 等相关工具，使用`POST`方法请求`http://127.0.0.1:5003/api/register`，记得带上 `body`参数。如:
```json
{
    "username": "maplewan",
    "password": "123"
}
```

# 实现登录登出功能（接口鉴权相关）

## 登录相关

### 1. 安装相关库实现Token的创建与校验

```shell
pip install Flask-JWT-Extended
```

### 2. `config.py`配置类中新增相关配置

- `JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")`
	- 作用：设置 JWT（JSON Web Token）签名和解密用的密钥。可参考[SECRET_KEY的作用](SECRET_KEY的作用.md)
	- 来源：通常从环境变量 .env 文件中读取，避免硬编码在代码里。
- `JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)`
	- 作用：设置 access token（访问令牌）的有效期，这里是 1 小时。
	- 含义：用户登录后获得的 access token 只能用 1 小时，过期后需要用 refresh token 换新。
	- 安全性：有效期短可以减少 token 泄露带来的风险。
- `JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)`
	- 作用：设置 refresh token（刷新令牌）的有效期，这里是 30 天。
	- 含义：refresh token 有效期更长，用户 access token 过期后可以用 refresh token 换取新的 access token，无需重新登录。
	- 安全性：refresh token 也要妥善保管，泄露后风险较大。
- `JWT_BLOCKLIST_TOKEN_CHECKS = ['access']`
	- 作用：指定哪些类型的 token 需要检查是否在 blocklist（黑名单）中。
	- 常见用法：比如用户登出、账号被封禁时，可以把某些 token 加入 blocklist，防止被继续使用。
	- `['access']`：只检查 access token 是否被拉黑。你也可以写 `['access', 'refresh']`，这样 access 和 refresh token 都会被检查。

```python
# app/config.py

# ...
from datetime import timedelta
# ...
class Config(object):
    # ...
    # JWT 相关配置
	JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") # 密钥
	JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1) # 1小时
	JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30) # 30天
	JWT_BLOCKLIST_TOKEN_CHECKS = ['access'] # 检查类型
	# ...
```

<font color="#ff0000">需要注意的是</font>：当你的 access token 是在 `14:01`获取得到的，那么你的`15:01`时失效，哪怕你在`15:00`的时候使用了它。这样的用户交互其实是有问题的。因此我们考虑“每次用token都自动延长有效期”，自己实现“滑动过期”机制。

- 通常做法是：每次用户操作时，检测access token快过期了，就用refresh token自动换一个新的access token。

因此我们在编写登录接口时（`login.py`），可以将access token的过期时间返回给前端，前端来检测当access token 快过期的时候（比如 `＜ 2min`），使用 refresh token 来重新拉取一下 access token
### 3. `.env`添加相关变量

```
# .env

# 登录验证相关参数
# JWT密钥
JWT_SECRET_KEY=3281700dd2dc233be7dcf77085e4d42172a1d74910f771576e46439a47281e73
```

### 4. 创建 Flask 应用时初始化 JWT 扩展
```python
# app/__init__.py

# ...
from flask_jwt_extended import JWTManager
# ...
def create_app(config_name):
    # ...
    # 初始化 JWT
    jwt = JWTManager(app)
    return app
# ...
```

### 5. 实现 login 相关接口

与实现“注册”功能类似，新建一个 `Login` 类，并且定义了一个 `post` 函数表明该接口是 POST 请求。因为登录接口传入的参数和注册接口一致，所以直接引入注册接口的校验函数。解析完参数后，判断该用户是否已经注册，如果没注册则抛出错误，如果注册了则进行密码校验，校验通过了就使用扩展提供的函数新建两个 Token，其中 `access_token` 是用来鉴权的，有效期 1 小时（在 `config.py` 中配置的）。

为了避免用户需要频繁的重新登录，再生成一个`refresh_token`，当`access_token` 过期后使用 `refresh_token` 来换取新的 `access_token`，当然，`refresh_token` 也有 30 天的有效期。 因此还需要写一个`get` 函数来实现通过`refresh_token`获取`access_token`。加上 `@jwt_required` 装饰器，当加上该装饰器时，JWT 扩展会为我们自动在调用此接口时做 Token 校验，它默认是只校验 `access_token` 的，在括号内传入 `refresh=True` 则表示用有效的 `refresh_token` 可以通过校验。

```python
# app/api/resources

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
```

### 6. 注册登录接口

```python
# app/__init__.py

from .resources.login import Login
api.add_resource(Login, '/login')
# api.add_resource(Login, '/login', '/refresh', '/test')  # 可以添加多个路由
```

### 7. 测试登录接口

可以使用 postman 等相关工具，请求`http://127.0.0.1:5003/api/login`，

1. `POST` 方法
请求`body`
```json
{
	"username": "admin",
	"password": "admin"
}
```

2. `GET` 方法
请求`header`，注意 `Authorization`的值为 `POST` 方法得到的 `refresh_token`
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc1MTI2ODg2OSwianRpIjoiZTVkZTEyNTItMDEzOC00ZjIwLTkxM2UtNjY3ZDdkNTY5ZTA4IiwidHlwZSI6InJlZnJlc2giLCJzdWIiOiJhZG1pbiIsIm5iZiI6MTc1MTI2ODg2OSwiY3NyZiI6ImZmODJlNmE0LTA3MzItNDkzYS05NjNlLWUwMDY4OTdmY2RhOCIsImV4cCI6MTc1Mzg2MDg2OX0.nfQAl015FxxMJKosTdYQj1y9_P2MJZsjp19kVJbnfpU
```

## 登出相关

在用户退出登录后，要销毁 Token。首先我们需要一个表来存放已经销毁的 Token，在 `app/api/models` 下新建 `revoked_token.py` 文件：

### 1. 创建数据库模型类：`revoked_token.py`

```python
# app/api/models/revoked_token.py

from . import db

class RevokedToken(db.Model):
    __tablename__ = 'revoked_token'

    id = db.Column(db.Integer(), primary_key=True, nullable=False, autoincrement=True, comment='主键ID')
    jti = db.Column(db.String(120), nullable=False, comment='JWT ID')

    def add(self):
        db.session.add(self)
        db.session.commit()

    # 检查 JWT ID 是否在黑名单中
    @classmethod
    def is_jti_blacklisted(cls, jti):
        return cls.query.filter_by(jti=jti).first() is not None
```

### 2. 创建登出服务类：`logout.py`

创建一个 `revoked_token` 表，用来存放已经销毁的 Token，并且定义一个查询的方法，用来查询 Token 是否已销毁。 然后在 `app/api/resources` 下新建 `logout.py` 写入登出接口逻辑：用户退出登录时，先获取到 Token 中的唯一标识 `jti` 然后将它加入销毁 Token 的表中。

```python
# app/api/resources/logout.py

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
```

### 3. 注册登出接口

```python
# app/__init__.py

from .resources.logout import Logout
api.add_resource(Logout, '/logout')
```

### 4. 注册JWT钩子函数，检查token是否在黑名单中

需要注册一个 JWT 扩展提供的钩子函数，用来校验 Token 是否在销毁列表中。在 `app/__init__.py` 中添加以下内容，这样当用户在调用需要鉴权的接口时，JWT 扩展会先调用钩子函数校验是否是已经销毁的 Token

```python
# app/__init__.py

# ...
from flask_jwt_extended import JWTManager
# ...

def create_app(config_name):
    # ...
    # 初始化 JWT
    jwt = JWTManager(app)
    register_JWT_hooks(jwt)
    return app

def register_JWT_hooks(jwt):
    # 注册JWT钩子函数，用于检查token是否在黑名单中
    @jwt.token_in_blocklist_loader
    def check_if_token_in_blocklist(jwt_header, jwt_payload):
        jti = jwt_payload['jti']
        return RevokedToken.is_jti_blacklisted(jti)

# ...
```

### 5. 更新数据库表

新增了一个 `revoked_token`的`Model`，需要更新一下数据库表，一下命令会在数据库中新建一个`revoked_token`表

```shell
flask db migrate -m "添加 revoked token 表"
flask db upgrade
```

### 6. 测试接口

url： `http://127.0.0.1:5003/api/logout`
method: `POST`
header: `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc1MTI4ODUyMiwianRpIjoiMjM0ZTczODUtZDQ5Yy00OTg2LWJlYjYtMDcxMjI0NGJlNTQzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzUxMjg4NTIyLCJjc3JmIjoiMzFmNDZjZWUtZDQ4Ni00ZDNmLWEyYmQtMWI3MTRhMzE4OWM2IiwiZXhwIjoxNzUxMjkyMTIyfQ.De01aQccl_MWK0srrcKKQSNgZ9bBqnopXuCI211a0AE`
response：
```json
{
    "success": true,
    "message": "退出成功",
    "data": null
}
```

接口调用成功之后如果再次调用，由于`access_token`已经失效，会报错，如下
```json
{
    "msg": "Token has been revoked"
}
```

## 查找所有用户

```python
# app/api/resources/user.py

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
```

```python
# app/__init__.py
from .resources.user import UserService
api.add_resource(UserService, '/user')
```

**测试接口**：`http://127.0.0.1:5003/api/user`

method: `POST`

header: `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc1MTI4ODUyMiwianRpIjoiMjM0ZTczODUtZDQ5Yy00OTg2LWJlYjYtMDcxMjI0NGJlNTQzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzUxMjg4NTIyLCJjc3JmIjoiMzFmNDZjZWUtZDQ4Ni00ZDNmLWEyYmQtMWI3MTRhMzE4OWM2IiwiZXhwIjoxNzUxMjkyMTIyfQ.De01aQccl_MWK0srrcKKQSNgZ9bBqnopXuCI211a0AE`，注意这里需要是`login`获取得到的 `access_token` 的值

# 解决跨域问题

## 1. python 相关库安装

```shell
pip install Flask-Cors
```

## 2. 在创建 Flask 应用时初始化

```python
# app/__init__.py

# ...
from flask_cors import CORS

def create_app(config_name):
	#...    
    # 解决跨域
    CORS(app)
    # ...
```

## 3. 为什么要解决跨域问题?


# 通过Dokcer部署

导出 python 依赖包：`pip freeze -l > requirements.txt`

TODO

# 总结

以上是 使用 python Flask 搭建具有登录注册功能的Restful API 基本后端代码模板。

代码地址：`https://github.com/MapleWan/flask_restful_template`

最终目录结构

```shell
.
├── app
│   ├── __init__.py
│   ├── api
│   │   ├── __init__.py
│   │   ├── common
│   │   │   └── utils.py
│   │   ├── models
│   │   │   ├── __init__.py
│   │   │   ├── revoked_token.py
│   │   │   └── user.py
│   │   ├── resources
│   │   │   ├── login.py
│   │   │   ├── logout.py
│   │   │   ├── register.py
│   │   │   └── user.py
│   │   └── schema
│   │       └── register_sha.py
│   ├── config.py
│   └── manage.py
├── requirements.txt
└── run.py
```

其实从以上目录结构可以看出，其实`models`和`resources`文件夹内还可以进一步按照模块来组织等等，更多最佳实践有待进一步探索