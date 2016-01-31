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

    @gen.coroutine
    def user_author(self):
        userid = token_decode(str(self.get_argument("authorization", None)), options.secret_key)['id']
        if userid:
            yield self.db.user.find({"id": userid}).count()

    @gen.coroutine
    def admin_author(self):
        userid = token_decode(str(self.get_argument("authorization", None)), options.secret_key)['id']
        if not userid:
            return None
        res = self.db.user.find({"id": userid}).distinct('admin_auth')
        if res:
            return userid['id']
        return None

class HomeHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        response = default_json_response()
        # self.write("Hello, world")
        self.write(response)
        # response = default_json_response()
        # res = yield self.db.user.find({}).count()
        # response['usernum'] = res
        # response['type'] = options.secret_key
        # if self.user_author:
        #     self.write(response)
        # self.finish()

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
        user = {'id': userid, 'username': str(username), 'password': passwd, 'email': str(email), 'admin_auth': 0 }
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
            response['msg'] = "The type of username or password is error"
            self.write(response)
            return
        user = self.db.user.find({"username": username})
        user_count = yield user.count()
        if not user_count:
            self.set_status(400)
            response['msg'] = "The user doesn't exit"
            self.write(response)
            return
        hashed = yield user.distinct("password")
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

class ChallengesHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        response = default_json_response()
        response['token'] = str(self.get_argument("authorization", None))
        if not self.current_user():
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return
        respone['challenges'] = {}
        challenges = yield self.db.challenge.find({})



