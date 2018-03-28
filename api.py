#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from abc import ABCMeta, abstractmethod
from datetime import datetime
import six
import scoring

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class ValidationError(Exception):
    pass


class Field(object):
    __metaclass__ = ABCMeta
    empty_values = (None, (), [], {}, '')

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    @abstractmethod
    def validate(self, value):
        pass


class CharField(Field):
    def validate(self, value):
        if not isinstance(value, six.string_types):
            raise ValidationError("Field must be a string")


class ArgumentsField(Field):
    def validate(self, value):
        if not isinstance(value, dict):
            raise ValidationError("Invalid arguments dictionary")


class EmailField(CharField):
    def validate(self, value):
        super(EmailField, self).validate(value)
        if "@" not in value:
            raise ValidationError("Invalid email address")


class PhoneField(Field):
    def validate(self, value):
        error_msg = "Invalid phone number"
        if not isinstance(value, six.string_types) and not isinstance(value, int):
            raise ValidationError(error_msg)
        if not str(value).startswith("7"):
            raise ValidationError(error_msg)


class DateField(Field):
    def validate(self, value):
        try:
            datetime.strptime(value, "%d.%m.%Y")
        except ValueError:
            raise ValidationError("Invalid date format")


class BirthDayField(DateField):
    def validate(self, value):
        super(BirthDayField, self).validate(value)
        date = datetime.strptime(value, '%d.%m.%Y')
        if datetime.now().year - date.year > 70:
            raise ValidationError("Invalid birthday")


class GenderField(Field):
    def validate(self, value):
        if value not in GENDERS:
            raise ValidationError("Invalid gender")


class ClientIDsField(Field):
    def validate(self, value):
        if not isinstance(value, (list, tuple)):
            raise ValidationError("Invalid data type, must be an array")
        if not all(isinstance(v, int) and v >= 0 for v in value):
            raise ValidationError("All elements must be positive integers")


class DeclarativeFieldsMetaclass(type):
    def __new__(mcs, name, bases, attrs):
        new_class = super(DeclarativeFieldsMetaclass, mcs).__new__(mcs, name, bases, attrs)
        fields = []
        for field_name, field in attrs.items():
            if isinstance(field, Field):
                field._name = field_name
                fields.append((field_name, field))
        new_class.fields = fields
        return new_class


class Request(object):
    __metaclass__ = DeclarativeFieldsMetaclass

    def __init__(self, **kwargs):
        self.errors = {}
        self.base_fields = []
        for field_name, value in kwargs.items():
            setattr(self, field_name, value)
            self.base_fields.append(field_name)

    def validate(self):
        for name, field in self.fields:
            if name not in self.base_fields:
                if field.required:
                    self.errors[name] = "Field is required"
                continue

            value = getattr(self, name)
            if value in field.empty_values and not field.nullable:
                self.errors[name] = "Field can't be blank"

            try:
                field.validate(value)
            except ValidationError as e:
                self.errors[name] = e.message

    def is_valid(self):
        return not self.errors


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


class Handler(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def process_request(self, request, context, store):
        pass


class ClientsInterestsHandler(Handler):
    def process_request(self, request, context, store):
        interests = ClientsInterestsRequest(**request.arguments)
        interests.validate()
        if not interests.is_valid():
            return interests.errors, INVALID_REQUEST

        response_body = {client_id: scoring.get_interests(store, client_id) for client_id in interests.client_ids}
        context["nclients"] = len(interests.client_ids)
        return response_body, OK


class OnlineScoreHandler(Handler):
    def process_request(self, request, context, store):
        score = OnlineScoreRequest(**request.arguments)
        score.validate()
        if not score.is_valid():
            return score.errors, INVALID_REQUEST

        context["has"] = score.base_fields
        score = 42 if request.is_admin else scoring.get_score(store, score.phone, score.email, score.birthday,
                                                              score.gender, score.first_name, score.last_name)
        return {"score": score}, OK


def check_auth(request):
    if request.login == ADMIN_LOGIN:
        digest = hashlib.sha512(datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    handlers = {
        "online_score": OnlineScoreHandler,
        "clients_interests": ClientsInterestsHandler
    }

    method_request = MethodRequest(**request["body"])
    method_request.validate()

    if not method_request.is_valid():
        return method_request.errors, INVALID_REQUEST
    if not check_auth(method_request):
        return None, FORBIDDEN

    handler = handlers[method_request.method]()
    result = handler.process_request(method_request, ctx, store)
    return result


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
