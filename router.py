import tornado.web
from tornado.options import options

import motor

import os.path


from handlers import HomeHandler, RegisterHandler, LoginHandler
from config import define



class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
            (r"/api/register", RegisterHandler),
            (r"/api/login", LoginHandler),
        ]
        settings = dict(
            blog_title = u"x",
            static_path = os.path.join(os.path.dirname(__file__), "static"),
            
            #ui_modules = {"Entry": EntryModule}, #Unkown
            
            # xsrf_cookies = True,
            cookie_secret = "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url = "/auth/login",
            
            xheaders = True,

            debug = options.debug,
            #serve_traceback = options.debug, #If true, the default error page will include the traceback of the error. 
        )
        super(Application, self).__init__(handlers, **settings)
        client = motor.motor_tornado.MotorClient('mongodb://localhost:27017')
        self.db = client.test
