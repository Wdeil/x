import tornado.httpserver
import tornado.ioloop
from tornado.options import options

from routes import Application
from config import define

def main():
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.current().start()
    
if __name__ == "__main__":
    main()