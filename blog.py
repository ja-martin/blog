import os
import webapp2
import hmac
import json
import jinja2
import random
import re
import string
import time
from google.appengine.ext import ndb
from google.appengine.api import memcache

############### GLOBAL VARIABLES ###############

JINJA_ENVIRONMENT = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
                                       extensions=['jinja2.ext.autoescape'],autoescape=True)

COOKIE_SECRET = 'secret'

RE_USERNAME = r'^[a-zA-Z0-9_-]{3,16}$'
RE_PASSWORD = r'^[a-zA-Z0-9_-]{3,18}$'
RE_EMAIL = r'^[\S]+@[\S]+\.[\S]+$'
RE_SUBJECT = r'^[a-zA-Z0-9_\s-]{3,50}$'
RE_URL = r'^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$'
RE_PATH = r'' #TODO
RE_CONTENT = r'^.{10,10000}$'


############### MODELS ###############

class Account(ndb.Model):
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True, indexed=False)
    email = ndb.StringProperty(required=True)

    @classmethod
    def exists_username(cls, username):
        """ Checks if the given username exists in the database. """
        if cls.query(cls.username == username).count() > 0:
            return True
        else:
            return False

class Category(ndb.Model):
    category = ndb.StringProperty(required=True)

class Post(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.StringProperty(required=True, indexed=False)
    image = ndb.StringProperty(default='http://placehold.it/400x240&text=[img]')
    category = ndb.StructuredProperty(Category)
    author = ndb.StructuredProperty(Account)
    date = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_recent(cls, limit=10):
        """ Returns most recent entries. """
        return cls.query().order(-cls.date).fetch(limit)

############### UTILS ###############

class Utils():

    ########### Security ############

    @staticmethod
    def random_salt():
        return ''.join(random.choice(string.letters) for i in range(5))

    @staticmethod
    def secured_cookie(value):
        h = hmac.new(COOKIE_SECRET, value).hexdigest()
        return str(value + '|' + h)

    @staticmethod
    def valid_cookie(cookie):
        s = cookie.split('|')
        value = s[0]
        h = s[1]
        return h == hmac.new(COOKIE_SECRET, value).hexdigest()

    @staticmethod
    def secured_password(password):
        salt = Utils.random_salt()
        h = hmac.new(salt, password).hexdigest()
        return str(h + ',' + salt)

    @staticmethod
    def valid_password(password, db_password):
        s = db_password.split(',')
        h = s[0]
        salt = str(s[1])
        return h == hmac.new(salt, password).hexdigest()

    ########### Validation ###########

    @staticmethod
    def valid_format(pattern, string, flags=0):
        prog = re.compile(pattern, flags=flags)
        return prog.match(string)

############### REQUEST HANDLERS ###############

class BasePage(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = JINJA_ENVIRONMENT.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def logged_in(self):
        """ Checks if user is logged in, trying to get a valid user cookie from the request. """
        cookie = self.request.cookies.get('user')

        if cookie and Utils.valid_cookie(cookie):
            return True
        else:
            return False

    def base_context(self, title):
        """ Returns a dictionary with context variables common to all pages. """
        context = {}

        context['title'] = title

        navlinks = []
        navlinks.append({'text': 'Home', 'href': '/home'})
        if self.logged_in():
            navlinks.append({'text': 'New post', 'href': '/newpost'})
            navlinks.append({'text': 'Logout', 'href': '/logout'})
        else:
            navlinks.append({'text': 'Login', 'href': '/login'})
            navlinks.append({'text': 'Sign up', 'href': '/signup'})
        context['navlinks'] = navlinks

        categories = memcache.get('categories')
        if not categories:
            categories = {}
            results = Category.query().fetch()
            for c in results:
                categories[c.category] = c
            memcache.set(key='categories', value=categories)
        context['categories'] = categories

        return context


class MainPage(BasePage):

    def get(self, *args):
        context = self.base_context('Home')

        recent_entries = self.get_recent_entries()

        if recent_entries:
            context['recent_entries'] = recent_entries

        self.render('/templates/index.html', **context)

    def get_recent_entries(self):
        recent_entries = memcache.get('recent_entries')

        if not recent_entries:
            recent_entries = Post.get_recent()

        if recent_entries:
            memcache.set(key='recent_entries', value=recent_entries)

        return recent_entries

class JsonMainPage(MainPage):

    def get(self):
        recent_entries = self.get_recent_entries()

        output = []
        for post in recent_entries:
            element = {}
            element['subject'] = post.subject
            element['content'] = post.content
            element['image'] = post.image
            element['author'] = post.author.username
            element['date'] = post.date.strftime('%Y-%m-%d %H:%M')
            output.append(element)

        self.response.content_type = 'application/json'
        self.write(json.dumps(output))

class NewPostPage(BasePage):

    def get(self):
        if self.logged_in():
            context = self.base_context('New Post')
            self.render('/templates/newpost.html', **context)
        else:
            self.redirect('/login')

    def post(self):
        if self.logged_in():
            subject = self.request.get('subject')
            content = self.request.get('content')
            image = self.request.get('image')
            category = self.request.get('category')

            valid_subject = Utils.valid_format(RE_SUBJECT, subject)
            valid_content = Utils.valid_format(RE_CONTENT, content, flags=re.DOTALL)
            valid_image = Utils.valid_format(RE_URL, image)

            if valid_subject and valid_content and valid_image:
                user_cookie = self.request.cookies.get('user')
                username, _ = user_cookie.split('|')
                account = memcache.get('account:{0}'.format(username))
                categories = memcache.get('categories')
                db_category = categories[category]

                newpost = Post(subject=subject,
                               content=content,
                               image=image,
                               category=db_category,
                               author=account)
                key = newpost.put()
                num_id = key.id()

                memcache.delete('recent_entries')
                memcache.set(key='post:{0}'.format(num_id), value=newpost)

                self.redirect('/post/{0}'.format(num_id))
            else:
                context = self.base_context('New Post')

                context['subject'] = subject
                context['content'] = content
                context['image'] = image

                if not valid_subject:
                    context['subject_err'] = 'Subject must have 3 to 50 characters'
                if not valid_content:
                    context['content_err'] = 'Content must have 10 to 10000 characters'
                if not valid_image:
                    context['image_err'] = 'Wrong image url format'

                self.render('/templates/newpost.html', **context)
        else:
            self.redirect('/login')

class PostPage(BasePage):

    def get(self, post_id):
        post = self.get_post(post_id)

        context = self.base_context(post.subject)
        context['post'] = post

        self.render('/templates/post.html', **context)

    def get_post(self, post_id):
        post = memcache.get('post:{0}'.format(post_id))

        if not post:
            post = ndb.Key(Post, post_id).get()
            memcache.set(key='post:{0}'.format(post_id), value=post)

        return post       

class JsonPostPage(PostPage):

    def get(self, post_id):
        post = self.get_post(post_id)

        output = {}
        output['subject'] = post.subject
        output['content'] = post.content
        output['image'] = post.image
        output['author'] = post.author.username
        output['date'] = post.date.strftime('%Y-%m-%d %H:%M')

        self.response.content_type = 'application/json'
        self.write(json.dumps(output))

class SignupPage(BasePage):

    def get(self):
        context = self.base_context('Sign up')
        self.render('/templates/signup.html', **context)

    def post(self):
        """ Validates signup form data sent by the user. Checks the following:
            - Username, password and email have a valid format.
            - Matching password and verification.
            - Username does not exist previously in the database.
            If there's any error, shows corresponding messages.
            When all data is correct, adds a user cookie to the response and redirects to main page.
        """
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        valid_username = Utils.valid_format(RE_USERNAME, username)
        valid_password = Utils.valid_format(RE_PASSWORD, password)
        valid_verify = not password or password == verify
        valid_email = not email or Utils.valid_format(RE_EMAIL, email)
        exists_username = Account.exists_username(username)

        if all([valid_username, valid_password, valid_verify, valid_email, not exists_username]):
            account = Account(username=username, 
                              password=Utils.secured_password(password), 
                              email=email)
            account.put()

            memcache.set(key='account:{0}'.format(account.username), value=account)
            self.response.headers.add_header('Set-Cookie', 'user={0};Path=/'.format(Utils.secured_cookie(username)))
            self.redirect('/home')
        else:
            context = self.base_context('Sign up')

            context['username'] = username
            context['email'] = email

            error_checking = [(not valid_username, 'username_err', 'Wrong username format'),
                              (exists_username, 'username_err', 'Username already exists'),
                              (not valid_password, 'password_err', 'Wrong password format'),
                              (not valid_verify, 'verify_err', "Passwords don't match"),
                              (not valid_email, 'email_err', 'Wrong email format')]

            for error_condition, context_var, error_msg in error_checking:
                if error_condition:
                    context[context_var] = error_msg

            self.render('/templates/signup.html', **context)

    
class LoginPage(BasePage):

    def get(self):
        if self.logged_in():
            self.redirect('/home')
        else:
            context = self.base_context('Login')
            self.render('/templates/login.html', **context)

    def post(self):
        """TODO
        """
        username = self.request.get('username')
        password = self.request.get('password')

        valid_username = Utils.valid_format(RE_USERNAME, username)
        valid_password = Utils.valid_format(RE_PASSWORD, password)

        context = self.base_context('Login')

        if valid_username and valid_password:
            # Only access database when username and password have valid formats.
            account = self.login(username, password)
            if account:
                memcache.set(key='account:{0}'.format(account.username), value=account)
                self.response.headers.add_header('Set-Cookie', 'user={0};Path=/'.format(Utils.secured_cookie(username)))
                self.redirect('/home')
            else:
                context['username'] = username
                context['username_err'] = 'Wrong username or password'

                self.render('/templates/login.html', **context)
        else:
            context['username'] = username
            if not valid_username:
                context['username_err'] = 'Wrong username format'
            if not valid_password:
                context['password_err'] = 'Wrong password format'

            self.render('/templates/login.html', **context)

    def login(self, username, password):
        """ Validates that given username account exists and passwords matches.
            Returns the account object when validation is successful.
        """
        account = Account.query(Account.username == username).get()

        if account and Utils.valid_password(password, account.password):
            return account
        else:
            return None


class LogoutPage(BasePage):

    def get(self):
        """TODO
        """
        if self.logged_in():
            user_cookie = self.request.cookies.get('user')
            username, _ = user_cookie.split('|')
            memcache.delete('account:{0}'.format(username))
            self.response.delete_cookie('user')

        self.redirect('/login')

class WelcomePage(BasePage):

    def get(self):
        user_cookie = self.request.cookies.get('user')
        if user_cookie and Utils.valid_cookie(user_cookie):
            self.response.out.write('Welcome %s!' % user_cookie.split('|')[0])
        else:
            self.redirect('/login')

class FlushPage(BasePage):

    def get(self):
        memcache.flush_all()
        self.redirect('/home')

application = webapp2.WSGIApplication([(r'(^/?$)|(^/home/?$)', MainPage),
                                       (r'/home\.json/?', JsonMainPage),
                                       (r'/newpost/?', NewPostPage),
                                       (r'/post/(\d+)/?', PostPage),
                                       (r'/post/(\d+)\.json/?', JsonPostPage),
                                       (r'/signup/?', SignupPage),
                                       (r'/login/?', LoginPage),
                                       (r'/logout/?', LogoutPage),
                                       (r'/welcome/?', WelcomePage),
                                       (r'/flush/?', FlushPage),
                                       ], debug=True)
