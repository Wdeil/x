from tornado import gen
import tornado.web
import tornado.options
import tornado.escape

import motor
import jwt

from utils import shortid_generate, check_uname_passwd, check_email, passwd_hash, check_passwd, default_json_response

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user = jwt.decode(self.get_argument("authorization", None), options.secret_key)
        if user and self.db.user.find({"_id": user}).count():
            return self.db.user.find_one({"_id": user})
        self.send_error(401)
        return False
        
        
class HomeHandler(BaseHandler):
    def get(self):
        self.write("Hello, world")

class RegisterHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        response = default_json_response()
        username = str(self.get_body_argument("username", None))
        password = str(self.get_body_argument("password", None))
        email = str(self.get_body_argument("email", None))
        if not check_uname_passwd(username, password) or not check_email(email):
            self.set_status(400)
            response['status'] = 400
            response['error'] = "The type of username or password or email is error"
            self.write(response)
            return
        userid = shortid_generate()
        passwd = passwd_hash(str(password))
        user = {'id': userid, 'username': str(username), 'password': passwd, 'email': str(email), }
        db_uname = yield self.db.user.find({'username': str(username)}).count()
        db_email = yield self.db.user.find({'email': str(email)}).count()
        if db_uname or db_email:
            self.set_status(400)
            response['status'] = 400
            if db_email and db_uname:
                response['error'] = "The email and username have exited"
            elif db_email:
                response['error'] = "The email have exited"
            else:
                response['error'] = "The username have exited"
            self.write(response)
            return 
        try:
            result = yield self.db.user.insert(user)
        except Exception as e:
            # add log here
            self.set_status(404)
            response['status'] = 404
            response['msg'] = "Register Error."
            self.write(response)
            return
        if result:
            self.set_status(201)
            response['status'] = 201
            response['msg'] = "Register Success"
            self.write(response)
            return

class LoginHandler(BaseHandler):
    def get(self):
        json = {"id": "fsdhfhskjdhfkjs"}
        self.write(tornado.escape.json_encode(json))
    
    def post(self):
        username = self.get_argument("username", None)
        password = self.get_argument("password", None)
        if not check_uname_passwd(username, password):
            self.set_status(400)
            self.write({"error": "the type of username or password is error"})
        passwd_hashed = self.db.user.find_one({"username": username})["password"]
        if bcrypt.hashpw(password, passwd_hashed) == passwd_hashed:
            pass