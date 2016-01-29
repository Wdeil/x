from tornado import gen
import tornado.web
from tornado.options import options
import tornado.escape

import motor

from utils import shortid_generate, check_uname_passwd, check_email, passwd_hash, check_passwd, default_json_response, token_encode, token_decode

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        response = default_json_response()
        userid = token_decode(str(self.get_argument("authorization", None)), options.secret_key)
        if not userid:
            return None
        res = self.db.user.find({"id": userid['id']}).count()
        if res:
            return userid['id']
        return None
        
        
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
            response['msg'] = "The type of username or password or email is error"
            self.write(response)
            return
        userid = shortid_generate()
        passwd = passwd_hash(str(password))
        user = {'id': userid, 'username': str(username), 'password': passwd, 'email': str(email), }
        db_uname = yield self.db.user.find({'username': str(username)}).count()
        db_email = yield self.db.user.find({'email': str(email)}).count()
        if db_uname or db_email:
            self.set_status(400)
            if db_email and db_uname:
                response['msg'] = "The email and username have exited"
            elif db_email:
                response['msg'] = "The email have exited"
            else:
                response['msg'] = "The username have exited"
            self.write(response)
            return 
        try:
            result = yield self.db.user.insert(user)
        except Exception as e:
            # add log here
            self.set_status(404)
            response['msg'] = "Register Error."
            self.write(response)
            return
        if result:
            self.set_status(201)
            response['msg'] = "Register Success"
            self.write(response)
            return

class LoginHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        response = default_json_response()
        username = str(self.get_body_argument("username", None))
        password = str(self.get_body_argument("password", None))
        if not check_uname_passwd(username, password):
            self.set_status(400)
            response['msg'] = "The type of username or password or email is error"
            self.write(response)
            return
        user_exist = yield self.db.user.find({"username": username}).count()
        if not user_exist:
            self.set_status(400)
            response['msg'] = "The user doesn't exit"
            self.write(response)
            return
        hashed = yield self.db.user.find({"username": username}).distinct("password")
        if check_passwd(password, str(hashed[0])):
            userid = yield user.distinct("id")
            token = token_encode({"id": userid}, options.secret_key)
            self.set_status(200)
            response['token'] = token
            response['msg'] = "Login Success"
            self.write(response)
            return
        self.set_status(401)
        response['msg'] = "The password was error"
        self.write(response)
        return






