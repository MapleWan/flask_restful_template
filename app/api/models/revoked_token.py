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