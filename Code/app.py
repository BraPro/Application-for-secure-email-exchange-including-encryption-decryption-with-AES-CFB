from flask import Flask, request, render_template
from Socket import Client
"""
run the server first then run the app!!, and log in the user list is the group:
4)user: kfir@gmail.com , password:kfir
4)user: shoval@gmail.com , password:shoval
4)user: roman@gmail.com , password:roman
4)user: rafa@gamil.com , password:rafa

if you got an email you need tor efresh to website in order to see it in the inbox, because the flask firmware it doesn't actually update his self.
"""

app = Flask(__name__)
client = Client


@app.route('/')
def index():
    return render_template('Login.html')


@app.route('/panel', methods=['POST'])
def panel():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['pass']
        result = client.login(email, password)
        print(result)
        result = client.getinbox(email)
        print("-" * 80)
        print("User '{}' Inbox".format(email))
        for single in result:
            print(single)
        print("-" * 80)
        source = {
            "email": email
        }
        return render_template('Panel.html', data=result, source=source)


@app.route('/send', methods=['POST'])
def send():
    if request.method == 'POST':
        source = request.form['source']
        to = request.form['to']
        message = request.form['msg']
        client.sendmsg(source, to, message)
        result = client.getinbox(source)
        print("-" * 80)
        print("User '{}' Inbox".format(source))
        for single in result:
            print(single)
        print("-" * 80)
        source = {
            "email": source
        }
        return render_template('Panel.html', data=result, source=source)


if __name__ == '__main__':
    app.run()

