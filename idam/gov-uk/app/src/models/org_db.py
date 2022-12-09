from src.db import db


class OrgDbModel(db.Model):
    __tablename__ = "organisation_table"
    id = db.Column(db.Integer, primary_key=True)
    establishment_name = db.Column(db.String(236), nullable=False, unique=False)
    address_1 = db.Column(db.String(236), nullable=False, unique=False)
    address_2 = db.Column(db.String(236), nullable=False, unique=False)
    county = db.Column(db.String(236), nullable=False, unique=False)
    country = db.Column(db.String(236), nullable=False, unique=False)
    city = db.Column(db.String(236), nullable=False, unique=False)
    post_code = db.Column(db.String(236), nullable=False, unique=False)
    web_address = db.Column(db.String(236), nullable=False, unique=False)
    general_email = db.Column(db.String(236), nullable=False, unique=False)
    email_domain = db.Column(db.String(236), nullable=False, unique=False)

    @classmethod
    def find_by_establishment_name(cls, _establishment_name):
        return cls.query.filter_by(establishment_name=_establishment_name).first()

    @classmethod
    def find_by_email_domain(cls, _email_domain):
        return cls.query.filter_by(email_domain=_email_domain).first()

    @classmethod
    def find_by_establishment_names_like(cls, criteria):
        return cls.query.filter(OrgDbModel.establishment_name.like(criteria)).all()

    @classmethod
    def find_by_address_1(cls, _address_1):
        return cls.query.filter_by(address_1=_address_1).first()

    @classmethod
    def find_by_general_email(cls, _general_email):
        return cls.query.filter_by(general_email=_general_email).first()

    @classmethod
    def find_by_post_code(cls, _post_code):
        return cls.query.filter_by(post_code=_post_code).first()

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
