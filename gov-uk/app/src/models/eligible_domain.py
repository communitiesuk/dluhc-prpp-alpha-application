from src.db import db


class DomainModel(db.Model):
    __tablename__ = "eligible_domains"
    id = db.Column(db.Integer, primary_key=True)
    domain_name = db.Column(db.String(80), nullable=False)

    @classmethod
    def find_by_domain_name(cls, domain_name):
        # SELECT * FROM items WHERE domain_name=domain_name LIMIT 1
        return cls.query.filter_by(domain_name=domain_name).first()

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
