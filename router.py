import tornado.web
from tornado.options import options

import motor

import os.path


from modules import HomeHandler
from config import define



class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
            (r"/", HomeHandler),
        ]
        settings = dict(
            blog_title = u"x",
            static_path = os.path.join(os.path.dirname(__file__), "static"),
            
            #ui_modules = {"Entry": EntryModule}, #Unkown
            
            xsrf_cookies = True,
            cookie_secret = "__TODO:_GENERATE_YOUR_OWN_RANDOM_VALUE_HERE__",
            login_url = "/auth/login",
            
            debug = options.debug,
            serve_traceback = options.debug, #If true, the default error page will include the traceback of the error. 
        )
        super(Application, self).__init__(handlers, **settings)
        # Have one global connection to the blog DB across all handlers
        client = motor.motor_tornado.MotorClient('mongodb://localhost:27017')
        self.db = client.test

    #     self.maybe_create_tables()

    # def maybe_create_tables(self):
    #     try:
    #         self.db.get("SELECT COUNT(*) from entries;")
    #     except MySQLdb.ProgrammingError:
    #         subprocess.check_call(['mysql',
    #                                '--host=' + options.mysql_host,
    #                                '--database=' + options.mysql_database,
    #                                '--user=' + options.mysql_user,
    #                                '--password=' + options.mysql_password],
    #                               stdin=open('schema.sql'))
