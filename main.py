import os
import webapp2
import jinja2

from google.appengine.ext import db

import time
import random
import string
import hashlib
import logging


def make_salt():
  return ''.join(random.choice(string.letters) for x in xrange(5))

# Implement the function valid_pw() that returns True if a user's password 
# matches its hash. You will need to modify make_pw_hash.

def make_pw_hash(name, pw, salt): 
  h = hashlib.sha256(name + pw + salt).hexdigest()
  return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
  s = h.split('|')[1]
  return make_pw_hash(name, pw, s) == h

# print valid_pw('spez', 'hunter21', h)


def hash_str(s):
  return hashlib.md5(s).hexdigest()

def make_secure_val(s):
  return "%s|%s" % (s, hash_str(s))

# -----------------
# User Instructions
# 
# Implement the function check_secure_val, which takes a string of the format 
# s,HASH
# and returns s if hash_str(s) == HASH, otherwise None 

def check_secure_val(h):
  ###Your code here
  t = h.split('|')
  if hash_str(t[0]) == t[1]:
    return t[0]
  else:
    return None

def autoesc(t):
  # skip autoescape for templates in the list bellow
  skip = ['page.html']
  return not t in skip



template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape= autoesc)



class Handler(webapp2.RequestHandler):
  def write(self, *a, **kw):
    self.response.out.write(*a, **kw)
  def render_str(self, template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
  def render(self, template, **kw):
    self.write(self.render_str(template, **kw))

  def loggedin(self):
    uidc = self.request.cookies.get('user_id')
    if uidc:
      uid = check_secure_val(uidc)
      if uid:
        user = User.get_by_id(long(uid))
        return user

def add_entry_to_history(wikipage, username):
  p = PageHistory(page=wikipage.key().name(), user=username, content = wikipage.content)
  p.put()

class PageHistory(db.Model):
  page = db.StringProperty(required = True)
  user = db.StringProperty(required = True)
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  
class WikiPage(db.Model):
  content = db.TextProperty(required = True)
  created = db.DateTimeProperty(auto_now_add = True)
  modiffied = db.DateTimeProperty(auto_now = True)
  
class User(db.Model):
  username = db.StringProperty(required = True)
  password_hash = db.StringProperty(required = True)
  email = db.StringProperty(required = False)
  created = db.DateTimeProperty(auto_now_add = True)  



class HistoryPage(Handler):
  def get(self, page):
    u = self.loggedin()
    hist = db.GqlQuery("SELECT * FROM PageHistory WHERE page=:1 ORDER BY created DESC", page)
    self.render("history.html", history=hist, page=page, user=u)


class WikiWebPage(Handler):
  def get(self, page):
    version = self.request.get('v')
    
    u = self.loggedin()
    if version:
      p = PageHistory.get_by_id(long(version))
    else:
      p = WikiPage.get_by_key_name(page)
    if p:
      self.render("page.html", content = p.content, page=page, user=u)
    else:
      if u:
        self.redirect('/_edit%s' % page)
      else:
        self.redirect('/login')

class SignUp(Handler):
    
  def get(self):
  
    self.render("signup.html")
    
  def post(self):
    # self.request.cookies.get(name)
    # self.response.headers.add_header('Set-Cookie', 'name=value; Path=/')
    
    username = self.request.get("username")
    password = self.request.get("password")
    verify = self.request.get("verify")
    email = self.request.get("email")

    
    users = db.GqlQuery("SELECT * FROM User where username = :1", username)
    if users.count() > 0:

      error = "user already exists. pick another! id: %d" % users.get().key().id()
      self.render("signup.html", username=username, email=email, error=error)
      return
    
      
    if username and password and password == verify:
      password_hash = make_pw_hash(username, password, make_salt())
    
      u = User(username=username, password_hash=password_hash, email=email)
      u.put()
      
      userid = u.key().id()
      
      self.response.headers.add_header('Set-Cookie', 'user_id='+ make_secure_val(str(userid)) +'; Path=/')
      self.redirect("/")
    else:
      error = "you need to type a username and the password to match!"
      self.render("signup.html", username=username, email=email, error=error)
class Logout(Handler):
  def get(self):
    self.response.headers.add_header('Set-Cookie', 'user_id= ; Path=/')
    self.redirect("/")
    
class Login(Handler):
    
  def get(self):
    logging.debug('booooooo')
    self.render("login.html")
    
  def post(self):
    
    username = self.request.get("username")
    password = self.request.get("password")

    user = db.GqlQuery("SELECT * FROM User where username = :1", username).get()
    
    if user and valid_pw(username, password, user.password_hash):
      userid = user.key().id()
      self.response.headers.add_header('Set-Cookie', 'user_id='+ make_secure_val(str(userid)) +'; Path=/')
      self.redirect("/")

    else:
      error = "wrong username or password!"
      self.render("login.html", username=username, error=error)      
      

class EditPage(Handler):
  def get(self, page):
    u = self.loggedin()
    version = self.request.get('v')
    if not u:
      self.redirect('/login')
      return

    p = self.get_wiki_page(page, version) 
    if p:
      self.render("edit.html", content=p.content, user=u, page=page, error='')
    else:
      self.render("edit.html", content='', user=u, page=page, error='')


  def get_wiki_page(self, page, version):
    if version:
      p = PageHistory.get_by_id(long(version))
    else:
      p = WikiPage.get_by_key_name(page)
    return p

  def post(self, page):
    u = self.loggedin()
    if not u:
      self.redirect('/login')
      return
    
    content = self.request.get("content")
    wp = WikiPage.get_or_insert(key_name=page, content=content)
    wp.content = content
    wp.put()
    add_entry_to_history(wp, u.username)
    self.redirect(page)
    

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

wiki = webapp2.WSGIApplication([
  ('/signup', SignUp),
  ('/login', Login),
  ('/logout', Logout), 
  ('/_edit' + PAGE_RE, EditPage),
  ('/_history' + PAGE_RE, HistoryPage),
  (PAGE_RE, WikiWebPage),
  
], debug=True)
