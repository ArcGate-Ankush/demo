from flask import Flask, make_response, render_template, request, redirect, flash, url_for, jsonify
import base64  # it is used to encode and decode data
import requests

ONELOGIN_CLIENT_ID = "c78a5930-c3b8-013a-0de5-0aff0ad712df210200"
ONELOGIN_CLIENT_SECRET = "945917ad647c3c80c8357eee9a8b910309a9533402f98d865802a06cf8b6c9d6"
ONELOGIN_SUBDOMAIN_URL = "flaskdummy-dev"
ONELOGIN_LOGIN_URL = "http://127.0.0.1:5000/login"
ONELOGIN_REDIRECT_URL = "http://127.0.0.1:5000/home"

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
            login_url = f"https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/auth?client_id={ONELOGIN_CLIENT_ID}&redirect_uri={url_for('home',_external = True, _scheme ='http')}&response_type=code&scope=openid"
            #  make_response is used to send custom headers as well as changing the property.
            response_value = make_response(redirect(login_url))
            # return redirect(login_url)
            return response_value, 301
        else:
            flash("Username  or Password is incorrect.", 'error')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'error' in request.args:
        if 'error_description' in request.args:
            flash(request.args['error_description'], 'error')
        else:
            flash('There was an error from OneLogin. Please contact admin', 'error')
        return redirect(url_for('login'))
    if 'code' in request.args:
        code = request.args['code']

        exchange_url = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/token'

        b64_encodeed_string = base64.b64encode(bytearray(
            f'{ONELOGIN_CLIENT_ID}:{ONELOGIN_CLIENT_SECRET}', 'utf-8')).decode('utf-8')

        headers = {'Content-Type': 'application/x-www-form-urlencoded',
                   'Authorization': f'Basic {b64_encodeed_string}'
                   }
        data = {
            "code": code,
            "redirect_uri": url_for('home', _external=True, _scheme='http'),
            "grant_type": 'authorization_code'
        }

        response = requests.post(exchange_url, data=data, headers=headers)
        response_data = response.json()
        onelogin_data['ONELOGIN_TOKEN_ID'] = response_data['id_token']
        print(response_data)
        if (response_data and response.status_code == 200):
            onelogin_data['access_token'] = response_data['access_token']
            onelogin_data['refresh_token'] = response_data['refresh_token']
            headers = {}
            headers['Authorization'] = f"Bearer {onelogin_data['access_token']}"
            user_info_url = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/me'
            user_info_response = requests.get(user_info_url, headers=headers)
            user_info_response_data = user_info_response.json()
            print(user_info_response_data)
            if (user_info_response_data and user_info_response.status_code == 200):
                name = user_info_response_data['preferred_username']
                email = user_info_response_data['email']
                if (details['username'] == name):
                    print(onelogin_data['ONELOGIN_TOKEN_ID'])
                    return render_template('home.html')
                flash(
                    'Name not exist. Please try again with other name or contact to admin', 'error')
            else:
                flash(user_info_response_data['error_description'], 'error')
        else:
            flash(response_data['error_description'], 'error')
        return redirect(url_for('login'))
    result = {
        'message': 'Please go to the chrome extension and login on chrome extension again .'}

    return make_response(jsonify(result)), 200


# @app.route('/logout', methods=['GET', 'POST'])
# def logout():
#     b64_encodeed_string = base64.b64encode(bytearray(
#         f'{ONELOGIN_CLIENT_ID}:{ONELOGIN_CLIENT_SECRET}', 'utf-8')).decode('utf-8')
#     headers = {'Content-type': 'application/x-www-form-urlencoded',
#                'Authorization': f"Basic {b64_encodeed_string}"}

#     endpoint = f'https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/token/revocation'
#     data = {
#         "token": onelogin_data['refresh_token'],
#         "token_type_hint": "refresh_token"
#     }
#     requests.post(endpoint, data=data, headers=headers)
#     response_make = make_response()
#     return response_make, 200


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_url = f"https://{ONELOGIN_SUBDOMAIN_URL}.onelogin.com/oidc/2/logout?post_logout_redirect_uri=http://127.0.0.1:5000&id_token_hint={onelogin_data['ONELOGIN_TOKEN_ID']}"
    print(logout_url)
    return redirect(logout_url)
if __name__ == '__main__':
    app.run(debug=True)
# ankush.pokharna@arcgate.com