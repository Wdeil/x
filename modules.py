from tornado import gen
import tornado.web
import tornado.options
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
        if  user and user == json.loads(self.get_argument("data", None))["_id"] and True:
            return True
        return None
        
    def any_author_exists(self):
        return bool(1)
        
class HomeHandler(BaseHandler):
    def get(self):
		self.write("Hello, world")

        
        
class ComposeHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        id = self.get_argument("id", None)
        entry = None
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
        self.render("compose.html", entry=entry)

    @tornado.web.authenticated
    def post(self):
        id = self.get_argument("id", None)
        title = self.get_argument("title")
        text = self.get_argument("markdown")
        html = markdown.markdown(text)
        if id:
            entry = self.db.get("SELECT * FROM entries WHERE id = %s", int(id))
            if not entry: raise tornado.web.HTTPError(404)
            slug = entry.slug
            self.db.execute(
                "UPDATE entries SET title = %s, markdown = %s, html = %s "
                "WHERE id = %s", title, text, html, int(id))
        else:
            slug = unicodedata.normalize("NFKD", title).encode(
                "ascii", "ignore")
            slug = re.sub(r"[^\w]+", " ", slug)
            slug = "-".join(slug.lower().strip().split())
            if not slug: slug = "entry"
            while True:
                e = self.db.get("SELECT * FROM entries WHERE slug = %s", slug)
                if not e: break
                slug += "-2"
            self.db.execute(
                "INSERT INTO entries (author_id,title,slug,markdown,html,"
                "published) VALUES (%s,%s,%s,%s,%s,UTC_TIMESTAMP())",
                self.current_user.id, title, slug, text, html)
        self.redirect("/entry/" + slug)
