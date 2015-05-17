import os
import re
import hmac
import random
import string
import hashlib
import json
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PW_RE = re.compile(r"^.{3,20}$")
EM_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

SECRET = 'b99201001'

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt=make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PW_RE.match(password)

def valid_email(email):
    return not email or EM_RE.match(email)

class User(db.Model):
    username = db.StringProperty(required = True)
    hashpw = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_json(self, d):
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json.dumps(d))

class Rot13(BaseHandler):
    def get(self):
        self.render("rot13-form.html")

    def post(self):
        rot13 = ''
        text = self.request.get('text')
        if text:
            rot13 = text.encode('rot13')

        self.render('rot13-form.html', text = rot13)

def cookie_make(username):
    return '%s|%s' % (username, hmac.new(SECRET, username).hexdigest())

def cookie_check_user(cookie):
    val = cookie.split('|')[0]
    return val if cookie_make(val) == cookie else None

class SignUp(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        have_error = False
        tmp_kargs = {'username': username, 'email': email}

        if not valid_username(username):
            have_error = True
            tmp_kargs['error_username'] = 'Invalid username!'

        if not valid_password(password):
            have_error = True
            tmp_kargs['error_password'] = 'Invalid password!'
        elif password != verify:
            have_error = True
            tmp_kargs['error_verify'] = 'Different password!'

        if not valid_email(email):
            have_error = True
            tmp_kargs['error_email'] = 'Invalid email!'

        if have_error:
            self.render("signup-form.html", **tmp_kargs)
        else:
            hashpw = make_pw_hash(username, password)
            cookie = str(cookie_make(username))
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % cookie )
            a = User(username = username, hashpw = hashpw)
            a.put()
            self.redirect('/')

class LogIn(BaseHandler):
    def get(self):
        self.render("login-form.html")

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        if username and password:
            u = User.all().filter('username =', username).get() 
            if u and valid_pw(username, password, u.hashpw):
                cookie = str(cookie_make(username))
                self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % cookie )
                self.redirect('/')
            else:
                error = 'invalid login'
                self.render("login-form.html", error=error)
        else:
            error = dict(username=username)
            if not username:
                error['error_username'] = 'please fillin username'
            if not password:
                error['error_password'] = 'please fillin password'
            self.render("login-form.html", **error)

class LogOut(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=; Path=/')
        self.redirect('/signup')

class Welcome(BaseHandler):
    def get(self):
        username_cookie = self.request.cookies.get('username', 'None')
        if cookie_check_user(username_cookie):
            self.render('welcome.html', username = username_cookie.split('|')[0])
        else:
            self.redirect('/signup')

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def toDict(self):
        d = dict(subject=self.subject, 
                 content=self.content,
                 created=self.created.strftime('%c'))
        return d

class blog(BaseHandler):
    def render_blog(self, *a):
        post = Post.get_by_id(int(a[0]))
        if self.request.url.endswith('.json'):
            self.render_json(post.toDict())
        else:
            self.render("blog.html", post=post)

    def get(self, *a):
        self.render_blog(*a)

class newpost(BaseHandler):
    def render_front(self, **kw):
        #posts = db.GqlQuery("select * from Post order by created desc")
        #kw['posts'] = posts
        self.render("front.html", **kw)

    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            p = Post(subject=subject, content=content)
            p.put()
            self.redirect('/blog/'+str(p.key().id()))
        else:
            if not subject:
                error = 'you must enter subject'
            else:
                error = 'you must write some content'
            self.render_front(**{'subject': subject, 'content': content, 'error': error})

class home(BaseHandler):
    posts = db.GqlQuery("select * from Post order by created desc")
    def render_home(self):
        self.render("home.html", posts=self.posts)

    def get(self):
        if self.request.url.endswith('.json'):
            self.render_json([p.toDict() for p in self.posts])
        else:
            self.render_home()


app = webapp2.WSGIApplication([('/blog', home),
                               ('/blog/.json', home),
                               ('/', Welcome),
                               ('/blog/signup', SignUp),
                               ('/blog/login', LogIn),
                               ('/blog/logout', LogOut),
                               ('/blog/rot13', Rot13),
                               ('/blog/newpost', newpost),
                               ('/blog/(\d+).json', blog),
                               ('/blog/(\d+)', blog)],
                               debug=True)
