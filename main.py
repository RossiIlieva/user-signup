#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
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
#
import webapp2
import cgi
import re


form="""
<form method="post">
    <h2>Signup</h2>
    <br>
    <label>
        Username
        <input type="text" name="username" value="%(username)s">
    </label>
     <span style="color:red">%(error_un)s</span>
    <br>
    <br>
    <label>
        Password
        <input type="password" name="password" value="%(password)s">
    </label>
    <span style="color:red">%(error_pw)s</span>
    <br>
    <br>
    <label>
        Verify password
        <input type="password" name="verify" value="%(verify)s">
    </label>
    <span style="color:red">%(error_match)s</span>
    <br>
    <br>
    <label>
        Email(Optional)
        <input type="text" name="email" value="%(email)s">

    </label>
    <span style="color:red">%(error_em)s</span>

    <br>
    <br>
    <input type="submit">
</form>
"""




USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return bool(username and USER_RE.match(username))

PASS_RE=re.compile(r"^.{3,20}$")
def valid_password(password):
    return bool(password and PASS_RE.match(password))

EMAIL_RE=re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return bool(not email or EMAIL_RE.match(email))








class MainHandler(webapp2.RequestHandler):
    """Handles requests coming in to '/' (The root of the site)
       e.g. www.user-signup.com/
    """
    def write_form(self, error_un="",error_pw="",error_em="",error_match="",username="", password="", verify="", email=""):
        self.response.out.write(form % {"error_un": error_un,
                                        "error_pw": error_pw,
                                        "error_em": error_em,
                                        "error_match":error_match,
                                        "username":username,
                                        "password": password,
                                         "verify": verify,
                                          "email": email})

    def get(self):
        self.write_form()

    def post(self):
        have_error=False
        user_username=self.request.get('username')
        user_password=self.request.get('password')
        verify=self.request.get('verify')
        user_email=self.request.get('email')
        username=valid_username(user_username)
        password=valid_password(user_password)
        email=valid_email(user_email)


        error_un="That's not a valid username."
        error_pw="That's not a valid password."
        error_em="That's not a valid email."
        error_match="Your passwords didn't match."


    #    if not (username and password and email):
    #        self.write_form(error_un,error_pw,error_em, "", user_username)

    #        have_error=True
    #    elif not (password and email):
    #        self.write_form("",error_pw,error_em,"",user_username)
    #        have_error=True


    #    elif not (username and password):
    #        self.write_form(error_un,error_pw,"","",user_username)
    #        have_error=True
    #    elif not (username and email):
    #        self.write_form(error_un,"",error_em,"",user_username)
    #        have_error=True
    #    elif not username:
    #        self.write_form(error_un,"","","",user_username)
    #        have_error=True
    #    elif not password:
    #        self.write_form("",error_pw,"","",user_username)
    #        have_error=True
    #    elif not email:
    #        self.write_form("","",error_em,"",user_username)
    #        have_error=True
    #    elif user_password !=verify:
    #        self.write_form("","","",error_match,user_username)
    #        have_error=True


    #    elif not have_error:
    #                self.redirect('/welcome?username='+ user_username)


        if username:
            if password:
                if email or user_email=="":
                    if user_password == verify:
                        self.redirect('/welcome?username='+ user_username)
                    else:
                        self.write_form("","","",error_match,user_username,"","",user_email)
                else:
                    self.write_form("","",error_em,"",user_username,"","",user_email)
            else:
                self.write_form("",error_pw,"","",user_username,"","",user_email)
        else:
            self.write_form(error_un,"","","",user_username,"","",user_email)



class Welcome(webapp2.RequestHandler):
    def get(self):
        user_username=self.request.get('username')
        content="<h2>" + "Welcome, " + user_username + "!" + "</h2>"
        self.response.write(content)







app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/welcome',Welcome)
], debug=True)
