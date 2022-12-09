from src.db import db


class AccessModel(db.Model):
    __tablename__ = "access_table"
    id = db.Column(db.Integer, primary_key=True)
    access_code = db.Column(db.String(36), nullable=False, unique=True)
    token_type = db.Column(db.String(36), nullable=False)
    expiry = db.Column(db.Integer, nullable=False)
    access_token = db.Column(db.String(2024), nullable=False)
    refresh_token = db.Column(db.String(2024), nullable=False)
    session_id = db.Column(db.String(2024), nullable=False)

    @classmethod
    def find_by_access_code(cls, access_code):
        # SELECT * FROM items WHERE access_code=access_code LIMIT 1
        return cls.query.filter_by(access_code=access_code).first()

    @classmethod
    def find_by_id(cls, _id):
        return cls.query.filter_by(id=_id).first()

    @classmethod
    def find_all(cls):
        return cls.query.all()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    def delete_from_db(self):
        db.session.delete(self)
        db.session.commit()

    def __repr__(self):
        return "<AccessModel(access_token={self.access_token!r})>".format(self=self)
