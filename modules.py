from tornado import gen
import tornado.web
import tornado.options
import tornado.escape

import jwt
import json
from shortid import ShortId
# sid = ShortId()
# print(sid.generate()) # dsHaFGMTL2id

class BaseHandler(tornado.web.RequestHandler):
    @property
    def db(self):
        return self.application.db

    def get_current_user(self):
        user = jwt.decode(self.get_argument("jsonwebtoken", None), options.secret_key)
        if  user and user == tornado.escape.json_decode(self.get_argument("data", None))["_id"] and db.user.find({"_id":user}).count():
            return db.user.find({"_id":user})
        return None
        
        
class HomeHandler(BaseHandler):
    def get(self):
		self.write("Hello, world")

 