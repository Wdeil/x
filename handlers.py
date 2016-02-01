from tornado import gen
import tornado.web
from tornado.options import options
import tornado.escape

import motor

from utils import shortid_generate, check_uname_passwd, check_email, passwd_hash, check_passwd, token_encode, token_decode, user_safe

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    @gen.coroutine
    def user_author(self):
        token = self.request.headers.get('authorization', '')
        if token:
            userid = str(token_decode(str(token), options.secret_key)['id'])
            user = yield self.db.user.find_one({"id": userid})
            if user:
                raise gen.Return(str(user.get('username', '')))
        raise gen.Return('')

    @gen.coroutine
    def admin_author(self):
        token = self.request.headers.get('authorization', '')
        if token:
            userid = str(token_decode(str(token), options.secret_key)['id'])
            user = yield self.db.user.find_one({"id": userid})
            if user and user.get('admin_auth', ''):
                raise gen.Return(str(user.get('username', ''))) 
        raise gen.Return('')

class HomeHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        response = {}
        # self.write("Hello, world")
        # self.write(response)
        res = yield self.db.user.find_one({'username': 'test'})
        res['passwd'] = str(type(res.get('password')))
        user_safe(res)
        response['user'] = str(res)
        username, admin = yield [self.user_author(), self.admin_author()]
        if username:
            response['username'] = username
        response['usernametype'] = str(type(username))
        if admin:
            response['admin'] = admin
        # if username:
        if res:
            headers = self.request.headers.get('authorization', '')
            response['head'] = str(type(headers))
            # response['usename1'] = str(username)
            # response['type1'] = str(type(username))
            self.write(response)
        else:
            # response['usename2'] = str(username)
            # response['type2'] = str(type(username))
            self.write('response')
        self.finish()

        # user_count = yield self.db.user.find({}).count()
        # response.add({'num': user_count})
        # self.write(response)

class RegisterHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        response = {}
        username = str(self.get_body_argument("username", ''))
        password = str(self.get_body_argument("password", ''))
        email = str(self.get_body_argument("email", ''))
        if not check_uname_passwd(username, password) or not check_email(email):
            self.set_status(400)
            response['msg'] = "The type of username or password or email is error"
            self.write(response)
            return
        userid = shortid_generate()
        passwd = passwd_hash(str(password))
        user = {'id': userid, 'username': str(username), 'password': passwd, 'email': str(email), 'admin_auth': 0, 'solved_id': [] }
        db_uname, db_email = yield [self.db.user.find({'username': str(username)}).count(), self.db.user.find({'email': str(email)}).count()]
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
        response = {}
        username = str(self.get_body_argument("username", ''))
        password = str(self.get_body_argument("password", ''))
        if not check_uname_passwd(username, password):
            self.set_status(400)
            response['msg'] = "The type of username or password is error"
            self.write(response)
            return
        user = yield self.db.user.find_one({"username": username})
        if not user:
            self.set_status(400)
            response['msg'] = "The user doesn't exit"
            self.write(response)
            return
        hashed = str(user.get('password'))
        if check_passwd(password, hashed):
            userid = str(user.get('id'))
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
        response = {}
        username = yield self.user_author()
        if not username:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return
        response['challenges'] = {}
        challenges, user = yield [self.db.challenges.find({}).sort('category').to_list(None), self.db.user.find_one({'username': username})]
        solved_id = user.get('solved_id', [])
        for challenge in challenges:
            if str(challenge['category']) not in response['challenges']:
                response['challenges'][str(challenge['category'])] = []
            docu = {'id': str(challenge['id']), 'description': str(challenge['description']), 'title': str(challenge['title']), 'value': str(challenge['value']), 'done': False}
            if challenge['id'] in solved_id:
                docu['done'] = True
            response['challenges'][str(challenge['category'])].append(docu)
        response['msg'] = "Get challenges Done"
        self.write(response)
        return

    @gen.coroutine
    def post(self):
        response = {}
        admin_name = yield self.admin_author()
        if not admin_name:
            self.set_status(401)
            response['msg'] = "Auth deny"
            self.write(response)
            return
        category = str(self.get_body_argument("category", None))
        title = str(self.get_body_argument("title", None))
        description = str(self.get_body_argument("description", None))
        value = str(self.get_body_argument("value", None))
        flag = str(self.get_body_argument("flag", None))
        challenge_id = shortid_generate()
        challenge = {'id': challenge_id, 'category': category, 'title': title, 'description': description, 'value': value, 'file': '', 'flag': flag,}
        try:
            result = yield self.db.challenges.insert(challenge)
        except Exception as e:
            # add log here
            self.set_status(404)
            response['msg'] = "Challenge Create Error."
            self.write(response)
            return
        if result:
            self.set_status(201)
            response['msg'] = "Challenge Create Success"
            self.write(response)
            return

class ChallengesIDHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        response = {}
        username = yield self.user_author()
        if not username:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return
        response['challenges'] = {}
        challenge_ID = self.request.uri.split("/")[3]
        challenge, user = yield [self.db.challenges.find_one({'id': challenge_ID}), self.db.user.find_one({'username': username})]
        solved_id = user.get('solved_id', [])
        if str(challenge['category']) not in response['challenges']:
            response['challenges'][str(challenge['category'])] = []
        docu = {'id': str(challenge['id']), 'description': str(challenge['description']), 'title': str(challenge['title']), 'value': int(challenge['value']), 'done': False}
        if challenge['id'] in solved_id:
            docu['done'] = True
        response['challenges'][str(challenge['category'])].append(docu)
        response['msg'] = "Get challenge Done"
        self.write(response)
        return        

    @gen.coroutine
    def delete(self):
        response = {}
        admin_name = yield self.admin_author()
        if not admin_name:
            self.set_status(401)
            response['msg'] = "Auth deny"
            self.write(response)
            return
        response['challenges'] = {}
        challenge_ID = self.request.uri.split("/")[3]
        challenge, users = yield [self.db.challenges.find_one({'id': challenge_ID}), self.db.user.find({}).sort('username').to_list(None)]
        delete_res = yield self.db.challenges.remove({'id': challenge_ID})
        #{u'ok': 1, u'n': 1}
        if delete_res['ok']:
            value = int(challenge['value'])
            for user in users:
                if challenge_ID in user.get('solved_id', []):
                    res = yield self.db.user.update({'id': str(user.get('id', ''))}, {'score': int(user.get('score', '')) - value})