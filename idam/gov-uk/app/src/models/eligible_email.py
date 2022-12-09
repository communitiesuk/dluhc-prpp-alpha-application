from src.db import db


class EmailModel(db.Model):
    __tablename__ = "eligible_emails"
    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.String(180), nullable=False)

    @classmethod
    def find_by_email(cls, email_address):
        # SELECT * FROM items WHERE email_address=email_address LIMIT 1
        return cls.query.filter_by(email_address=email_address).first()

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
