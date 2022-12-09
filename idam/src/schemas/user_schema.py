from marshmallow import Schema, fields


class UserType:
    USER = "User"
    AGENT = "AGENT"
    LANDLORD = "LANDLORD"

class User:
    def __init__(
        self,
        data={
            "username": "",
            "name": "",
            "family_name": "",
            "phone_number": "",
            "password": "",
            "email": "",
            "organisation": "",
            "organisation_role": "",
            "terms": "0",
            "user_type": UserType.USER,
            "pool_name": "",
        },
    ):
        self.username = data["username"]
        self.name = data["name"]
        self.family_name = data["family_name"]
        self.phone_number = data["phone_number"]
        self.password = data["password"]
        self.email = data["email"]
        self.organisation = data["organisation"]
        self.organisation_role = data.get("organisation_role", "")
        self.terms = data["terms"]
        self.user_type = data["user_type"]
        self.pool_name = data["pool_name"]

    def __repr__(self):
        return "<User(username={self.username!r})>".format(self=self)


class LandlordUser(User):
    def __init__(
        self,
        data={
            "username": "",
            "name": "",
            "family_name": "",
            "phone_number": "",
            "password": "",
            "email": "",
            "organisation": "",
            "organisation_role": "",
            "address_line_1": "",
            "address_line_2": "",
            "city": "",
            "county": "",
            "country": "",
            "postcode": "",
            "how_found": "",
            "before": "0",
            "terms": "0",
            "permission": "0",
            "user_type": UserType.LANDLORD,
            "pool_name": "",
            "client_id": "",
        },
    ):
        User.__init__(
            self,
            data=data,
        )
        self.organisation_role = data.get("organisation_role", "")
        self.address_line_1 = data.get("address_line_1", "")
        self.address_line_2 = data.get("address_line_2", "")
        self.city = data.get("city", "")
        self.county = data.get("county", "")
        self.country = data.get("country", "")
        self.postcode = data.get("postcode", "")
        self.before = data.get("before", "")
        self.permission = data.get("permission", "")
        self.how_found = data.get("how_found", "")
        self.user_type = UserType.LANDLORD,

    def __repr__(self):
        return "<LandlordUser(username={self.username!r})>".format(self=self)


class AgentUser(User):
    def __init__(
        self,
        data={
            "username": "",
            "name": "",
            "family_name": "",
            "phone_number": "",
            "password": "",
            "email": "",
            "organisation": "",
            "organisation_role": "",
            "address_line_1": "",
            "address_line_2": "",
            "city": "",
            "county": "",
            "country": "",
            "postcode": "",
            "how_found": "",
            "before": "0",
            "permission": "",
            "terms": "0",
            "user_type": UserType.AGENT,
            "pool_name": "",
            "client_id": "",
        },
    ):
        User.__init__(
            self,
            data=data,
        )
        self.organisation_role = data.get("organisation_role", "")
        self.address_line_1 = data.get("address_line_1", "")
        self.address_line_2 = data.get("address_line_2", "")
        self.city = data.get("city", "")
        self.county = data.get("county", "")
        self.country = data.get("country", "")
        self.postcode = data.get("postcode", "")
        self.before = data.get("before", "")
        self.how_found = data.get("how_found", "")
        self.permission = data.get("permission", "")
        self.user_type = UserType.AGENT

    def __repr__(self):
        return "<AgentUser(username={self.username!r})>".format(self=self)


class UserSchema(Schema):
    username = fields.Str(required=True)
    name = fields.Str(required=True)
    family_name = fields.Str(required=True)
    phone_number = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)
    organisation = fields.Str(required=True)
    organisation_role = fields.Str(required=False)
    terms = fields.Str(required=True)
    user_type = fields.Str(required=True)
    pool_name = fields.Str(required=True)
    client_id = fields.Str(required=False)

class AgentSchema(Schema):
    username = fields.Str(required=True)
    name = fields.Str(required=True)
    family_name = fields.Str(required=True)
    phone_number = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)
    organisation = fields.Str(required=True)
    organisation_role = fields.Str(required=False)
    terms = fields.Str(required=True)
    user_type = fields.Str(required=True)
    pool_name = fields.Str(required=True)
    client_id = fields.Str(required=False)

class LandlordSchema(Schema):
    username = fields.Str(required=True)
    name = fields.Str(required=True)
    family_name = fields.Str(required=True)
    phone_number = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)
    organisation = fields.Str(required=True)
    organisation_role = fields.Str(required=False)
    terms = fields.Str(required=True)
    user_type = fields.Str(required=True)
    pool_name = fields.Str(required=True)
    client_id = fields.Str(required=False)
    

class LoginSchema(Schema):
    username = fields.Str(required=True)
    user_type = fields.Str(required=True)
    name = fields.Str(required=True)
    family_name = fields.Str(required=True)
    phone_number = fields.Str(required=True)
    password = fields.Str(required=True)
    email = fields.Email(required=True)
    organisation = fields.Str(required=True)
    terms = fields.Str(required=True)
    redirect_uri = fields.Str(required=True)
    pool_name = fields.Str(required=True)
    client_id = fields.Str(required=False)


class SetPasswordSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)
    permanent = fields.Bool(required=True)


class CreateUserSchema(Schema):
    username = fields.Str(required=True)
    password = fields.Str(required=True)


class ChangeUsernameSchema(Schema):
    new_username = fields.Str(required=True)


class ChangePasswordSchema(Schema):
    username = fields.Str(required=True)
    old_password = fields.Str(required=True)
    new_password = fields.Str(required=True)
    client_id = fields.Str(required=True)


class ResendEmailVerificationSchema(Schema):
    username = fields.Str(required=True)


class ForceVerificationSchema(Schema):
    username = fields.Str(required=True)
