from tornado import gen
import tornado.web
from tornado.options import options
import tornado.escape

import motor
import os
import hashlib
# import json
import datetime

from utils import shortid_generate, check_uname_passwd, check_email, passwd_hash, check_passwd, token_encode, token_decode, user_safe, secure_filename

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    @gen.coroutine
    def user_author(self):
        token = self.request.headers.get('authorization', '').split(' ')[1]
        if token:
            userid = str(token_decode(str(token), options.secret_key)['id'])
            user = yield self.db.users.find_one({"id": userid})
            if user:
                raise gen.Return(str(userid))
        raise gen.Return('')

    @gen.coroutine
    def admin_author(self):
        token = self.request.headers.get('authorization', '').split(' ')[1]
        if token:
            userid = str(token_decode(str(token), options.secret_key)['id'])
            user = yield self.db.users.find_one({"id": userid})
            if user and user.get('admin_auth', False):
                raise gen.Return(str(userid)) 
        raise gen.Return('')

class HomeHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        response = {}
        # res = yield self.db.test.insert({'title': 'test'})
        # res = yield self.db.users.update({'username': 'test3'}, {'$set': {'score': 200}})
        # res = yield self.db.users.find({"username" : "", "email" : "test@test.com"}).count()
        #"{'updatedExisting': True, u'nModified': 1, u'ok': 1, u'n': 1}"
        # response['update'] = str(res)
        # response['ip'] = self.request.remote_ip
        # if res:
        #     response['res'] = str(res)
        #     response['msg'] = 'find one'
        # else:
        #     response['res'] = str(res)
        #     response['msg'] = 'not find one'


        self.write(response)

        # self.write("Hello, world")
        # self.write(response)
        # res = yield self.db.users.find_one({'username': 'test'})
        # res['passwd'] = str(type(res.get('password')))
        # user_safe(res)
        # response['user'] = str(res)
        # username, admin = yield [self.user_author(), self.admin_author()]
        # if username:
        #     response['username'] = username
        # response['usernametype'] = str(type(username))
        # if admin:
        #     response['admin'] = admin
        # # if username:
        # if res:
        #     headers = self.request.headers.get('authorization', '')
        #     response['head'] = str(type(headers))
        #     # response['usename1'] = str(username)
        #     # response['type1'] = str(type(username))
        #     self.write(response)
        # else:
        #     # response['usename2'] = str(username)
        #     # response['type2'] = str(type(username))
        #     self.write('response')
        # self.finish()

        # user_count = yield self.db.users.find({}).count()
        # response.add({'num': user_count})
        # self.write(response)
    @gen.coroutine
    def post(self):
        response = {}
        files = self.request.files
        # files = self.get_body_argument('files', '')
        # with open('result.txt', 'a') as f:
        #     f.write(files)
        # for x in files:
        #     with open('test1.exe', 'w') as f:
        #         f.write(files[x][0].get('body', ''))
        response['files'] = str(files)
        response['filestype'] = str(type(files))
        self.write(response)

class RegisterHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        response = {}
        username = str(self.get_body_argument("username", ''))
        password = str(self.get_body_argument("password", ''))
        email = str(self.get_body_argument("email", ''))
        coutry = str(self.get_body_argument("coutry", ''))
        if not check_uname_passwd(username, password) or not check_email(email):
            self.set_status(400)
            response['msg'] = "The type of username or password or email is error"
            self.write(response)
            return

        userid = shortid_generate()
        passwd = passwd_hash(str(password))
        user = {'id': userid, 'username': str(username), 'password': passwd, 'email': str(email), 'coutry': coutry, 'admin_auth': False, 'score': 0, 'banned': False}
        db_uname, db_email = yield [self.db.users.find({'username': str(username)}).count(), self.db.users.find({'email': str(email)}).count()]
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
            result = yield self.db.users.insert(user)
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
        else:
            self.set_status(404)
            response['msg'] = "Register Error"
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

        user = yield self.db.users.find_one({"username": username})
        if not user:
            self.set_status(400)
            response['msg'] = "The user doesn't exit"
            self.write(response)
            return

        hashed = str(user.get('password', ''))
        if check_passwd(password, hashed):
            userid = str(user.get('id', ''))
            token = token_encode({"id": userid}, options.secret_key)
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
        user_id = yield self.user_author()
        admin_id = yield self.admin_author()
        if not user_id:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return

        response['challenges'] = {}
        challenges, user_solves = yield [self.db.challenges.find({}).sort('category').to_list(None), self.db.solves.find({'userid': user_id}).to_list(None)]
        solved_id = []
        for docu in user_solves:
            solved_id.append(str(docu.get('chalid', '')))

        for challenge in challenges:
            if bool(challenge.get('hidden', False)) and not admin_id:
                continue

            if str(challenge.get('category', '')) not in response['challenges']:
                response['challenges'][str(challenge.get('category', ''))] = []
            docu = {'id': str(challenge.get('id', '')), 'description': str(challenge.get('description', '')), 'title': str(challenge.get('title', '')), 'value': int(challenge.get('value', 0)), 'fileslocation': [], 'done': False}
            
            if challenge.get('id', '') in solved_id:
                docu['done'] = True
            if challenge.get('files', False):
                files = yield self.db.files.find({'chalid': str(challenge.get('id', ''))}).to_list(None)
                for f in files:
                    docu['fileslocation'].append(str(f.get('location', '')))
            if admin_id:
                docu['hidden'] = bool(challenge.get('hidden', False))
                docu['flag'] = str(challenge.get('flag', ''))

            response['challenges'][str(challenge.get('category', ''))].append(docu)

        response['msg'] = "Get challenges Done"
        self.write(response)
        return

    @gen.coroutine
    def post(self):
        response = {}
        admin_id = yield self.admin_author()
        if not admin_id:
            self.set_status(401)
            response['msg'] = "Auth deny"
            self.write(response)
            return
        
        category = str(self.get_body_argument("category", ''))
        title = str(self.get_body_argument("title", ''))
        description = str(self.get_body_argument("description", ''))
        value = int(self.get_body_argument("value", 0))
        flag = str(self.get_body_argument("flag", ''))
        if not category or not title or not description or not value or not flag:
            self.set_status(400)
            response['msg'] = "Malformed Request"
            self.write(response)
            return
        
        challenge_id = shortid_generate()
        challenge = {'id': challenge_id, 'category': category, 'title': title, 'description': description, 'value': value, 'flag': flag, 'files': False, 'hidden': False}
        
        files = self.request.files
        if files:
            challenge['files'] = True
        for filelist in files:
            for afile in files[filelist]:
                filename = secure_filename(afile.get('filename', ''))
                if not len(filename):
                    continue
                md5hash = hashlib.md5(os.urandom(64)).hexdigest()
                if not os.path.exists(os.path.join(os.path.normpath(self.settings.get("static_path")), 'uploads', md5hash)):
                    os.makedirs(os.path.join(os.path.normpath(self.settings.get("static_path")), 'uploads', md5hash))
                location = os.path.join(os.path.normpath(self.settings.get("static_path")).split('/')[-1], 'uploads', md5hash, filename)
                with open(location, 'w') as f:
                    f.write(afile.get('body', ''))
                file_res = yield self.db.files.insert({'chalid': challenge_id, 'location': location})
                if not file_res:
                    self.set_status(404)
                    response['msg'] = "File Create Error."
                    self.write(response)
                    return

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
        user_id = yield self.user_author()
        admin_id = yield self.admin_author()
        if not user_id:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return

        response['challenges'] = {}
        challenge_ID = self.request.uri.split("/")[3]
        challenge, user_solved = yield [self.db.challenges.find_one({'id': challenge_ID}), self.db.solves.find({'userid': user_id, 'chalid': challenge_ID}).count()]
        if not challenge or bool(challenge.get('hidden', False)) and not admin_id:
            self.set_status(400)
            response['msg'] = "Malformed Request"
            self.write(response)
            return

        if str(challenge.get('category', '')) not in response['challenges']:
            response['challenges'][str(challenge.get('category', ''))] = []
        docu = {'id': str(challenge.get('id', '')), 'description': str(challenge.get('description', '')), 'title': str(challenge.get('title', '')), 'value': int(challenge.get('value', 0)), 'fileslocation': [], 'done': False}

        if user_solved:
            docu['done'] = True

        if challenge.get('files', False):
            files = yield self.db.files.find({'chalid': str(challenge.get('id', ''))}).to_list(None)
            for f in files:
                docu['fileslocation'].append(str(f.get('location', '')))
        if admin_id:
            docu['hidden'] = bool(challenge.get('hidden', False))
            docu['flag'] = str(challenge.get('flag', ''))

        response['challenges'][str(challenge.get('category', ''))].append(docu)
        response['msg'] = "Get challenge Done"
        self.write(response)
        return        

    @gen.coroutine
    def delete(self):
        response = {}
        admin_id = yield self.admin_author()
        if not admin_id:
            self.set_status(401)
            response['msg'] = "Auth deny"
            self.write(response)
            return

        challenge_ID = self.request.uri.split("/")[3]
        challenge, solved_users = yield [self.db.challenges.find_one({'id': challenge_ID}), self.db.solves.find({'chalid': challenge_ID}).to_list(None)]
        if not challenge:
            self.set_status(400)
            response['msg'] = "Malformed Request"
            self.write(response)
            return
 
        delete_res, files_delete = yield [self.db.challenges.remove({'id': challenge_ID}), self.db.files.remove({'id': challenge_ID})]
        if delete_res['ok']:
            value = int(challenge.get('value', 0))
            error_user = []
            for solved_user in solved_users:
                user = yield self.db.users.find_one({'id': str(solved_user.get('userid', ''))})
                res = yield self.db.users.update({'id': str(user.get('id', ''))}, {'$set': {'score': int(user.get('score', 0)) - value}})
                if not res['ok']:
                    error_user.append(str(user.get('id', '')))
            if error_user:
                response['unfinished_modify_user'] = error_user
                response['msg'] = 'Some user are not modified'
                self.write(response)
                return
            response['msg'] = 'Delete ' + challenge_ID + ' Success'
            self.write(response)
        else:
           response['msg'] = 'Delete ' + challenge_ID + ' Error'
           self.write(response)
        return

    @gen.coroutine
    def put(self):
        response = {}
        admin_name = yield self.admin_author()
        if not admin_name:
            self.set_status(401)
            response['msg'] = "Auth deny"
            self.write(response)
            return

        category = str(self.get_body_argument("category", ''))
        title = str(self.get_body_argument("title", ''))
        description = str(self.get_body_argument("description", ''))
        value = int(self.get_body_argument("value", 0))
        flag = str(self.get_body_argument("flag", ''))
        if not category or not title or not description or not value or not flag:
            self.set_status(400)
            response['msg'] = "Malformed Request"
            self.write(response)
            return

        challenge_ID = self.request.uri.split("/")[3]
        challenge = yield self.db.challenges.find_one({'id': challenge_ID})
        if not challenge:
            self.set_status(400)
            response['msg'] = "Malformed Request"
            self.write(response)
            return

        docu_update = {'category': category, 'title': title, 'description': description, 'value': value, 'flag': flag,}

        files = self.request.files
        if files:
            remove_files_res = yield self.db.files.remove({'chalid': challenge_ID}) #don't remove files, This only remove the index of files in database
        for filelist in files:
            for afile in files[filelist]:
                filename = secure_filename(afile.get('filename', ''))
                if not len(filename):
                    continue
                md5hash = hashlib.md5(os.urandom(64)).hexdigest()
                if not os.path.exists(os.path.join(os.path.normpath(self.settings.get("static_path")), 'uploads', md5hash)):
                    os.makedirs(os.path.join(os.path.normpath(self.settings.get("static_path")), 'uploads', md5hash))
                location = os.path.join(os.path.normpath(self.settings.get("static_path")).split('/')[-1], 'uploads', md5hash, filename)
                with open(location, 'w') as f:
                    f.write(afile.get('body', ''))
                file_res = yield self.db.files.insert({'chalid': challenge_id, 'location': location})
                if not files_res:
                    self.set_status(404)
                    response['msg'] = "File Create Error."
                    self.write(response)
                    return

        c_res_upda = yield self.db.challenges.update({'id': str(challenge.get('id', ''))}, {'$set':  docu_update})
        if not c_res_upda['ok']:
            self.set_status(404)
            response['msg'] = "Change " + challenge_ID + " Error"
            self.write(response)
            return
       
        diff_value = challenge.get('value', 0) - value
        if diff_value:
            solved_users = yield self.db.solves.find({'chalid': challenge_ID}).to_list(None)
            for solved_user in solved_users:
                user = yield self.db.users.find_one({'id': str(solved_user.get('userid', ''))})
                user_score = int(user.get('score', 0)) + diff_value
                u_res_upda = yield self.db.users.update({'id': str(user.get('id', ''))}, {'$set':  {'score': user_score}})
                if not u_res_upda['ok']:
                    self.set_status(404)
                    response['msg'] = "Change user score Error"
                    self.write(response)
                    return
        
        response['msg'] = "Change " + challenge_ID + " Success"
        self.write(response)
        return

    @gen.coroutine
    def post(self):
        response = {}
        user_id = yield self.user_author()
        if not user_id:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return

        flag = str(self.get_body_argument("flag", ''))
        challenge_ID = self.request.uri.split("/")[3]
        challenge, user, repeat = yield [self.db.challenges.find_one({'id': challenge_ID}), self.db.users.find_one({'id': user_id}), self.db.solves.find({'userid': user_id, 'chalid': challenge_ID}).count()]
        if not challenge or not flag:
            self.set_status(400)
            response['msg'] = "Malformed Request"
            self.write(response)
            return

        docu = {'chalid': challenge_ID,\
                 'userid': user_id, \
                 'flag': flag, \
                 'date': datetime.datetime.utcnow().isoformat(),\
                 'category': str(challenge.get('category', '')), \
                 'title': str(challenge.get('title', '')), \
                 'value': int(challenge.get('value', 0)), \
                 'ip': self.request.remote_ip}

        if challenge.get('flag', '') and challenge.get('flag', '') == flag:
            if repeat:
                response['msg'] = 'Submit Flag Success'
                self.write(response)
                return
            user_score = int(user.get('score', 0)) + int(challenge.get('value', 0))
            res = yield self.db.users.update({'id': user_id}, {'$set': {'score': user_score}})
            if not res['ok']:
                self.set_status(404)
                response['msg'] = "Submit Flag Error"
                self.write(response)
                return

            res = yield self.db.solves.insert(docu)
            response['msg'] = 'Submit Flag Success'
        else:
            res = yield self.db.fails.insert(docu)
            response['msg'] = 'The Flag is wrong'
        
        self.write(response)
        return

class TeamsHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        response = {'team': [], 'timeline': {}}
        user_id = yield self.user_author()
        admin_id = yield self.admin_author()
        if not user_id:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return

        users, start_time_D = yield [self.db.users.find({}).sort('score', -1).to_list(None), self.db.config.find_one({'key': 'start_time'})]
        
        start_time = str(start_time_D['value'])
        finish_time = datetime.datetime.utcnow().isoformat()
        same_num = 1
        place = 0
        pre_score = -1
        for user in users:
            docu =  {'id': str(user.get('id', '')), 'username': str(user.get('username', '')), 'score': int(user.get('score', 0))}
            if not user.get('banned', False):
                score = int(user.get('score', 0))
                if score != pre_score:
                    place += same_num
                    pre_score = score
                    same_num = 1
                else:
                    same_num += 1
                docu['place'] = place
                response['team'].append(docu)
                if place <= 10:
                    user_score = 0
                    timeline = [[start_time, user_score]]
                    solves = yield self.db.solves.find({'userid': str(user.get('id', ''))}, {'date': 1, 'value': 1, '_id': 0}).to_list(None)
                    for solve in solves:
                        user_score += solve.get('value', 0)
                        timeline.append([solve.get('date', ''), user_score])
                    timeline.append([finish_time, user_score])
                    response['timeline'][str(user.get('username', ''))] = timeline
                
            elif admin_id:
                if 'banned' not in response:
                    response['banned'] = []
                response['banned'].append(docu)

        response['msg'] = 'Get teams Success'
        self.write(response)

class TeamsIDHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        response = {'solved': [], 'failed': 0, 'score': 0, 'place': 0, }  
        user_id = yield self.user_author()
        admin_id = yield self.admin_author()
        if not user_id:
            self.set_status(401)
            response['msg'] = "User doesn't login"
            self.write(response)
            return

        user_ID = self.request.uri.split("/")[3]
        user, solves, failed = yield [self.db.users.find_one({'id': user_ID}), self.db.solves.find({'userid': user_ID}).sort('date', -1).to_list(None), self.db.fails.find({'userid': user_ID}).count()]
        response['failed'] = failed
        response['score'] = user.get('score', 0)
        place = yield self.db.users.find({'score': {'$gt': user.get('score', 0)}}).count()
        response['place'] = place + 1

        for solve in solves:
            docu = {'category': str(solve.get('category', '')), 'title': str(solve.get('title', '')), 'date': str(solve.get('date', '')), 'value': int(solve.get('value', 0))}
            response['solved'].append(docu)

        response['msg'] = 'Get ' + user_ID + ' Information Success'


        self.write(response)

    @gen.coroutine
    def delete(self):
        pass
        # response = {}
        # admin_id = yield self.admin_author()
        # if not admin_id:
        #     self.set_status(401)
        #     response['msg'] = "Auth deny"
        #     self.write(response)
        #     return

        # user_ID = self.request.uri.split("/")[3]

        # users_res, solves_res, fails_res = yield [self.db.challenges.remove({'id': challenge_ID}), self.db.challenges.remove({'id': challenge_ID}), self.db.challenges.remove({'id': challenge_ID}),]
        






