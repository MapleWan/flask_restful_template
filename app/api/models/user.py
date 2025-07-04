from . import db
from datetime import datetime
from ..common.utils import format_datetime_to_json

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