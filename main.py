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

#html boilerplate for the top of every page.
page_header="""
<!DOCTYPE html>
<html>
<head>
  <title>Signup</title>
  <style type="text/css">
      .error{color:red;
      }
  </style>
</head>
<body>
</body>
</html>
"""
USER_RE=re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE=re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE=re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)








class MainHandler(webapp2.RequestHandler):
        """Handles requests coming in to '/' (The root of the site)
           e.g. www.user-signup.com/
        """
    def write_form(self,error="",username="",password="",verify="",email=""):
        self.response.out.write(form%{"error":error,
                                      "username":username,
                                      "password":password,
                                      "verify":verify,
                                      "email":email})

    def get(self):
        self.write.form()

    def post(self):
        have_error=False
        user_username=self.request.get('username')
        user_password=self.request.get('password')
        verify=self.request.get('verify')
        user_email=self.request.get('email')
        username=valid_username(user_username)
        password=valid_password(user_password)
        if not username:
            self.write_form("That's not a valid username",user_username,)
            have_error=True
        if not password:
            self.write_form("That's not a valid password",)
            have_error=True
        elif password !=verify:
            self.write_form("Your passwords didn't match.")
            have_error=True
        if not email:
            self.write_form("That's not a valid email.")
            have_error=True
        if have_error:
            self.write_form()
        else:
            self.redirect('/welcome?username='+username)


class Welcome(webapp2.RequestHandler):
    def get(self):
        username=self.request.get('username')
        content="<h2>" + "Welcome, " + username + "!" + "</h2>"
        self.response.write(content)







app = webapp2.WSGIApplication([
    ('/', MainHandler)
], debug=True)
