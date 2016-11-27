# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import webapp2
import jinja2
import re  # for regex (regular expressions) i.e. form validation
import hmac
import hashlib
import random
import string
import time
from google.appengine.ext import db


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
                                loader=jinja2.FileSystemLoader(template_dir),
                                autoescape=True)

secret = "gm60dmwS$jaq5KmskaRka82V"


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

        # Hashes a string, passing in the global variable 'secret'.
    def hash_str(self, s):
        return hmac.new(secret, str(s)).hexdigest()

        # Saves the value and the hash of the value + 'secret' in a cookie.
    def hash_str_cookie(self, s):
        return "%s|%s" % (s, self.hash_str(s))

        # Checks cookie is valid by comparing the value to the hash.
    def check_cookie_hash(self, s):
        val = str(s).split('|')[0]
        if s == self.hash_str_cookie(val):
            return val

        # Sets cookie
    def set_secure_cookie(self, name, val):
        cookie_val = self.hash_str_cookie(val)
        self.response.headers.add_header(
                                        "Set-Cookie", "%s = %s; "
                                        "Expires=Fri,31-Dec-2017 "
                                        "23:59:59 GMT;Path=/"
                                        % (name, cookie_val))

        # Checks user is logged in
    def logincheck(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_cookie_hash(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.logincheck('user_id')
        self.user = uid and User.get_by_id(int(uid))

        # Retrieves the user ID from cookies
    def get_user_id(self):
        # Gets the cookie
        user_id = self.request.cookies.get("user_id")
        # Returns an int of the value from the cookie
        user_id = int(self.check_cookie_hash(user_id))
        # Gets the entity from the datastore
        retrieve_user_key = db.Key.from_path('User', user_id)
        return db.get(retrieve_user_key)

        # Removes a named cookie from browser based on the 'name' parameter
    def clear_cookie(self, name):
        self.response.headers.add_header(
                                        "Set-Cookie",
                                        "%s=; Path=/"
                                        % (name))

        # To generate a random 5 digit salt
    def make_salt(self):
        return ''.join(random.choice(string.letters) for x in xrange(5))

        # To make a salted hash of the password input, passing in 'salt'
        # as a parameter if it is present i.e. if the password has
        # already been set
    def make_pw_hash(self, username, password, salt=None):
        if not salt:
            salt = self.make_salt()
        h = hashlib.sha256(username + password + salt).hexdigest()
        return '%s|%s' % (h, salt)

        # To check a password is the same as the password in the datastore
        # (passing in the salt value as mentioned in make_pw_hash
    def valid_pw(self, username, password, h):
        saltrepeat = h.split("|")[1]
        if h == self.make_pw_hash(username, password, saltrepeat):
            return True

        # Checks to see that the blog post was posted by the logged in user
    def check_author(self, user_id, blog_post_id):
            if user_id == blog_post_id:
                return True

    def delete_object(self, model, obj_id, user, error):
        object_to_delete = model.get_by_id(int(obj_id))
        current_user = user.key()
        object_author = object_to_delete.user.key()
        # Checks if the logged in user posted the blog.
        if self.check_author(current_user, object_author):
            object_to_delete.delete()
            # Removes the initial error
            error = ""
            time.sleep(1)
        self.render(
            "blog.html",
            blog_posts=self.blog_posts,
            user=self.get_user_id(),
            error=error)


# User sign-up stuff


class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class UserSignUpHandler(Handler):

    # Three regular expressions to ensure the formatting is correct.
    def valid_username(self, username):
        user_re = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return user_re.match(username)

    def valid_password(self, password):
        password_re = re.compile(r"^.{3,20}$")
        return password_re.match(password)

    def valid_email(self, email):
        email_re = re.compile(r"^[\S]+@[\S]+.[\S]+$")
        if email == "":
            return True
        if email_re.match(email):
            return True

# Checks input is valid based on the above three functions
# & checks passwords match.
    def valid_user_input(self, username, password, password_clone, email):
        if (
            self.valid_username(username) and
            self.valid_password(password) and
            password == password_clone and
            self.valid_email(email)):
            return True

    def get(self):
        self.render("usersignup.html")

    def post(self):
        # Gets the form inputs and sets the errors to empty string
        username = self.request.get("username")
        username_error = ""
        password = self.request.get("password")
        password_error = ""
        verify = self.request.get("verify")
        verify_error = ""
        email = self.request.get("email")
        email_error = ""

        # Checks to see if input is valid
        if self.valid_user_input(username, password, verify, email):
            # Checks to see if the username already exists,
            # returns error if so.
            user_check = db.GqlQuery(
                                    "SELECT * FROM User WHERE username=:1",
                                    username)
            user_dup_check = user_check.get()
            if user_dup_check:
                username_error = "That username already exists."
                self.render(
                    "usersignup.html", username_return=username,
                    username_error=username_error)
            # otherwise saves the user in the datastore
            else:
                entry = User(
                            username=username,
                            password=self.make_pw_hash(username, password))
                entry.put()
                user_id = entry.key().id()
                # Sets Cookie for username
                self.set_secure_cookie("user_id", user_id)
                self.redirect("/blog")
        # Else determines where the error is and displays the relevant message.
        else:
            if not self.valid_username(username):
                username_error = "Invalid username!"
            if not self.valid_password(password):
                password_error = "Invalid password!"
            else:
                if not password == verify:
                    verify_error = "Your passwords don't match!"
            if not self.valid_email(email):
                email_error = "Invalid email!"
            self.render("usersignup.html",
                        username_return=username,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error)


class LoginHandler(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        error = ""
        if username and password:
            # Gets user id
            user_search = User.all().filter("username = ", username).get()
            if user_search:
                user_id = user_search.key().id()
                pw = user_search.password
            # Checks password with salted hash
                if self.valid_pw(username, password, pw):
                    self.set_secure_cookie("user_id", user_id)
                    self.redirect("/blog")
            else:
                error = "Invalid login."
        else:
            error = "Please enter a username and a password."
        self.render("login.html", error=error)


class LogoutHandler(Handler):
    def get(self):
        self.clear_cookie("user_id")
        self.redirect("/blog/login")

# Blog stuff


class Blog(db.Model):
    user = db.ReferenceProperty(User, collection_name="user_blog_posts")
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    # Returns the number of likes per blog post.
    def count_likes(self):
        return Likes.all().filter("blog_post = ", self).count()

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    # Returns the correctly rendered blog posts (iterable for post.html)
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return self.render_str(
                            "post.html",
                            b=self,
                            blog_id=self.key().id(),
                            comments=self.blog_comments.order("-created"))


class Comment(db.Model):
    user = db.ReferenceProperty(User, collection_name="user_comments")
    blog_post = db.ReferenceProperty(Blog, collection_name="blog_comments")
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)


class Likes(db.Model):
    user = db.ReferenceProperty(User, collection_name="user_likes")
    blog_post = db.ReferenceProperty(Blog, collection_name="blog_likes")

# Front page


class BlogHandler(Handler):
    # Selects all blog posts
    blog_posts = Blog.all().order('-created')

    def get(self):
        # Checks login
        if not self.user:
            self.redirect("/blog/login")
        else:
            self.render(
                "blog.html",
                blog_posts=self.blog_posts,
                user=self.get_user_id())

    def post(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            user = self.get_user_id()
            current_user = user.key()

            if self.request.POST.get("comment"):
                # Puts comment in datastore
                blog_post = Blog.get_by_id(int(self.request.get("blogid")))
                comment = self.request.get("comment_text")
                entry = Comment(
                                user=user,
                                blog_post=blog_post,
                                comment=comment)
                entry.put()
                time.sleep(1)
                self.redirect("/blog")

            elif self.request.POST.get("edit"):
                # Picks out the ID from the relevant
                # blog from the hidden input in the html
                blog_post = Blog.get_by_id(int(self.request.get("blogid")))
                blog_author = blog_post.user.key()
                error = "You may only edit your own posts."
                if self.check_author(current_user, blog_author):
                    self.redirect(
                                "/blog/edit?blog_post=%s"
                                % blog_post.key().id())
                else:
                    self.render(
                        "blog.html",
                        blog_posts=self.blog_posts,
                        user=self.get_user_id(),
                        error=error)

            elif self.request.POST.get("delete"):
                blog_id = self.request.get("blogid")
                self.delete_object(
                                    Blog,
                                    blog_id,
                                    user,
                                    "You may only delete your own posts.")

            elif self.request.POST.get("like"):
                blog_post = Blog.get_by_id(int(self.request.get("blogid")))
                blog_author = blog_post.user.key()
                error = "You cannot like your own posts."
                if not self.check_author(current_user, blog_author):
                    # Checking to see if the user has liked this post before
                    like_search = db.GqlQuery(
                        "SELECT * FROM Likes WHERE user=:1 AND blog_post=:2",
                        user, blog_post)
                    like_check = like_search.get()
                    # And returns an error if so
                    if like_check:
                        error = "You can only like a post once."
                    # Otherwise places the like in the datastore
                    else:
                        entry = Likes(user=user, blog_post=blog_post)
                        entry.put()
                        # And removes the initial error
                        error = ""
                        time.sleep(1)
                self.render(
                    "blog.html",
                    blog_posts=self.blog_posts,
                    user=user,
                    error=error)

            elif self.request.POST.get("commentdelete"):
                comment = self.request.get("comment_id")
                self.delete_object(
                                    Comment,
                                    comment,
                                    user,
                                    "You may only delete your own comments.")

            elif self.request.POST.get("commentedit"):
                comment = Comment.get_by_id(
                                        int(self.request.get("comment_id")))
                comment_author = comment.user.key()
                error = "You may only edit your own comments."
                if self.check_author(current_user, comment_author):
                    self.redirect(
                            "/blog/editcomment?commentid=%s"
                            % comment.key().id())
                else:
                    self.render(
                        "blog.html",
                        blog_posts=self.blog_posts,
                        user=self.get_user_id(),
                        error=error)


# POST INPUT PAGE i.e. /blog/newpost


class NewPostHandler(Handler):
    def get(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            self.render("newpost.html")

    def post(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            subject = self.request.get("subject")
            content = self.request.get("content")
            user = self.get_user_id()
            if subject and content:
                entry = Blog(subject=subject, content=content, user=user)
                entry.put()
                blogid = str(entry.key().id())
                time.sleep(1)
                self.redirect("/blog")
            else:
                error = "Please enter both 'subject' and 'content'"
                self.render(
                    "newpost.html",
                        error=error,
                        subject=subject,
                        content=content)

# EDITS


class EditHandler(Handler):
    def get(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            # Getting the blog id from the URL
            blog_post = Blog.get_by_id(int(self.request.get("blog_post")))
            self.render(
                "edit.html",
                subject=blog_post.subject,
                content=blog_post.content,
                blog_id=blog_post.key().id())

    def post(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            if self.request.POST.get("cancel"):
                self.redirect("/blog")
            else:
                user = self.get_user_id()
                current_user = user.key()
                # Gets the id from the hidden input in the form
                blogid = Blog.get_by_id(int(self.request.get("blogid")))
                if self.check_author(current_user, blogid.user.key()):
                    # Modifies the entity in the datastore
                    blogid.subject = self.request.get("subject")
                    blogid.content = self.request.get("content")
                    blogid.put()
                    time.sleep(1)
                    self.redirect("/blog")
                else:
                    self.redirect("/blog")

class CommentEditHandler(Handler):
    def get(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            # Getting the comment id from the URL
            comment = Comment.get_by_id(int(self.request.get("commentid")))
            self.render(
                "editcomment.html",
                comment=comment.comment,
                commentid=comment.key().id())

    def post(self):
        if not self.user:
            self.redirect("/blog/login")
        else:
            if self.request.POST.get("cancel"):
                self.redirect("/blog")
            else:
                user = self.get_user_id()
                current_user = user.key()
                # Gets the id from the hidden input in the form
                commentid = Comment.get_by_id(
                                    int(self.request.get("commentid")))
                if self.check_author(current_user, commentid.user.key()):
                    # Modifies the entity in the datastore
                    commentid.comment = self.request.get("comment")
                    commentid.put()
                    time.sleep(1)
                    self.redirect("/blog")
                else:
                    self.redirect("/blog")

# ONE POST PAGE:


# class PostPage(Handler):
#     def get(self, postid):
#         # takes 'postid' as 'blogid' from NewPostHandler
#         retrieve_post_key = db.Key.from_path('Blog', int(postid))
#         post = db.get(retrieve_post_key)
#         if not post:
#             self.error(404)
#             return
#         self.render("permalink.html", post=post)

app = webapp2.WSGIApplication([
    ('/blog', BlogHandler),
    ('/blog/edit', EditHandler),
    ('/blog/editcomment', CommentEditHandler),
    ('/blog/', BlogHandler),
    ('/blog/newpost', NewPostHandler),
    # ('/blog/([0-9]+)', PostPage),
    ('/blog/signup', UserSignUpHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler),
], debug=True)
