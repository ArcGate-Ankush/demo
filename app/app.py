from datetime import datetime, timedelta
from pickle import NONE
from flask import Flask, make_response, render_template, request, redirect, flash, url_for, jsonify
import base64  # it is used to encode and decode data
import requests
import uuid

ONELOGIN_CLIENT_ID = "c78a5930-c3b8-013a-0de5-0aff0ad712df210200"
ONELOGIN_CLIENT_SECRET = "945917ad647c3c80c8357eee9a8b910309a9533402f98d865802a06cf8b6c9d6"
ONELOGIN_SUBDOMAIN_URL = "flaskdummy-dev"
ONELOGIN_LOGIN_URL = "http://127.0.0.1:5000/login"
ONELOGIN_REDIRECT_URL = "http://127.0.0.1:5000/oidc-callback"

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisasecretkey'

details = {}

onelogin_data = {}


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():

    if(request.method == 'POST'):
        details['username'] = request.form['username']
        details['password'] = request.form['password']
        if(details['username'] == "ankush.pokharna@arcgate.com" and details['password'] == "abc"):
            print("we are here")
            login_url = f"https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/auth?client_id={ONELOGIN_CLIENT_ID}&redirect_uri={url_for('oidcCallback',_external = True, _scheme ='http')}&response_type=code&scope=openid"
            #  make_response is used to send custom headers as well as changing the property.
            response_value = make_response(redirect(login_url))
            response_value.set_cookie('SESSION_TOKEN_COOKIE_NAME', '',
                                      expires=0)
            response_value.set_cookie('SESSION_EMAIL', '',
                                      expires=0)
            # return redirect(login_url)
            return response_value, 301
        else:
            flash("Username  or Password is incorrect.", 'error')
            return redirect(url_for('login'))
    cookies_session_token = request.cookies.get(
        'SESSION_TOKEN_COOKIE_NAME', None)
    if cookies_session_token and onelogin_data['session_token_cookie_name'] == cookies_session_token:
        b64_encodeed_string = base64.b64encode(bytearray(
            f'{ONELOGIN_CLIENT_ID}:{ONELOGIN_CLIENT_SECRET}', 'utf-8')).decode('utf-8')

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': f'Basic {b64_encodeed_string}'
                   }
        if datetime.utcnow() < onelogin_data['session_expiration']:
            endpoint = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/token/introspection'
            data = {
                "token": onelogin_data['access_token'],
                "token_type_hint": "access_token"
            }
            response = requests.post(endpoint, data=data, headers=headers)
            response_data = response.json()
            if response_data and response.status_code == 200 and response_data['active']:
                return redirect(url_for('home'))
            data = {
                "refresh_token": onelogin_data['refresh_token'],
                "grant_type": "refresh_token"
            }
            endpoint = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/token'
            response = requests.post(
                endpoint, data=data, headers=headers)
            response_data = response.json()
            if response_data and response.status_code == 200:
                expire_date = datetime.utcnow()
                expire_date = expire_date + timedelta(minutes=1)
                session_token = uuid.uuid4().hex
                onelogin_data['access_token'] = response_data['access_token']
                onelogin_data['refresh_token'] = response_data['refresh_token']
                onelogin_data['id_token'] = response_data['id_token']
                onelogin_data['session_token_cookie_name'] = session_token
                onelogin_data['session_expiration'] = expire_date
                response_make = make_response(redirect(url_for('home')))
                response_make.set_cookie('SESSION_TOKEN_COOKIE_NAME', session_token,
                                         expires=expire_date, secure=True)
                response_make.set_cookie('SESSION_EMAIL', onelogin_data['email'],
                                         expires=expire_date, secure=True)

                return response_make, 301

    return render_template('login.html')


@app.route('/oidc-callback', methods=['GET', 'POST'])
def oidcCallback():
    if 'error' in request.args:
        if 'error_description' in request.args:
            flash(request.args['error_description'], 'error')
        else:
            flash('There was an error from OneLogin. Please contact admin', 'error')
        return redirect(url_for('login'))
    if 'code' in request.args:
        onelogin_data['code'] = request.args['code']

        exchange_url = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/token'

        b64_encodeed_string = base64.b64encode(bytearray(
            f'{ONELOGIN_CLIENT_ID}:{ONELOGIN_CLIENT_SECRET}', 'utf-8')).decode('utf-8')

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': f'Basic {b64_encodeed_string}'
                   }
        data = {
            "code": onelogin_data['code'],
            "redirect_uri": url_for('oidcCallback', _external=True, _scheme='http'),
            "grant_type": 'authorization_code'
        }
        # getting access, refresh and id token in exchange of authorization code
        response = requests.post(exchange_url, data=data, headers=headers)
        response_data = response.json()
        if (response_data and response.status_code == 200):
            onelogin_data['id_token'] = response_data['id_token']
            onelogin_data['access_token'] = response_data['access_token']
            onelogin_data['refresh_token'] = response_data['refresh_token']

            headers = {}
            headers['Authorization'] = f"Bearer {onelogin_data['access_token']}"
            user_info_url = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/me'
            # getting personal info by using access_token
            user_info_response = requests.get(user_info_url, headers=headers)
            user_info_response_data = user_info_response.json()
            if (user_info_response_data and user_info_response.status_code == 200):
                onelogin_data['name'] = user_info_response_data['preferred_username']
                onelogin_data['email'] = user_info_response_data['email']
                if (details['username'] == onelogin_data['name']):
                    expire_date = datetime.utcnow()
                    expire_date = expire_date + timedelta(minutes=1)
                    onelogin_data['session_expiration'] = expire_date
                    session_token = uuid.uuid4().hex
                    onelogin_data['session_token_cookie_name'] = session_token
                    response_make = make_response(redirect(url_for('home')))
                    response_make.set_cookie('SESSION_TOKEN_COOKIE_NAME', session_token,
                                             expires=expire_date, secure=True)
                    response_make.set_cookie('SESSION_EMAIL', onelogin_data['email'],
                                             expires=expire_date, secure=True)
                    return response_make
                else:
                    flash(
                        'Name not exist. Please try again with other name or contact to admin', 'error')
                    return redirect('logout')
            else:
                flash(user_info_response_data['error_description'], 'error')
        else:
            flash(response_data['error_description'], 'error')
        return redirect(url_for('login'))
    result = {
        'message': 'Please go to the chrome extension and login on chrome extension again .'}

    return make_response(jsonify(result)), 200


@app.route('/home')
def home():
    cookies_session_token = request.cookies.get(
        'SESSION_TOKEN_COOKIE_NAME', None)
    cookies_session_email = request.cookies.get('SESSION_EMAIL', None)
    if(not cookies_session_token and not cookies_session_email):
        if(onelogin_data['id_token']=='' and onelogin_data['access_token']=='' and onelogin_data['refresh_token']==''):
            return redirect(url_for('login'))
        return redirect(url_for('logout'))
    return make_response(render_template('home.html'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_url = f"https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/logout?post_logout_redirect_uri=http://127.0.0.1:5000&id_token_hint={onelogin_data['id_token']}"
    # response_make = make_response(redirect(logout_url))
    onelogin_data['id_token'] = ''
    onelogin_data['access_token'] = ''
    onelogin_data['refresh_token'] = ''
    res = make_response(redirect(logout_url))
    res.set_cookie('SESSION_TOKEN_COOKIE_NAME', '',
                                      expires=0)
    res.set_cookie('SESSION_EMAIL', '', expires=0)
    # onelogin_data['email']=''
    # onelogin_data['code']=''
    # onelogin_data['name']=''
    # onelogin_data['session_expiration']=''
    # onelogin_data['session_token_cookie_name']=''
    return res


if __name__ == '__main__':
    app.run(debug=True)
# ankush.pokharna@arcgate.com
