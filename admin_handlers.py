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
        if not userid['id']:
            return None
        res = self.db.user.find({"id": userid['id']}).distinct('admin_auth')
        if res:
            return userid['id']
        return None

class 
