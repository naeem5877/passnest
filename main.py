from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import firebase_admin
from firebase_admin import credentials, auth, db
from firebase_admin.exceptions import FirebaseError

app = Flask(__name__)
app.secret_key = 'YOUR_SECRET_KEY'  # Change to your secret key

    # Initialize Firebase
cred = credentials.Certificate('database.json')
firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://lyrical-respect-389317-default-rtdb.firebaseio.com/'
    })

@app.route('/')
def home():
        return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']

            try:
                user = auth.get_user_by_email(email)
                if user:
                    session['uid'] = user.uid
                    return redirect(url_for('index'))
            except FirebaseError:
                flash("Invalid email or password")
                return redirect(url_for('login'))

        return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if password != confirm_password:
                flash("Passwords do not match.")
                return redirect(url_for('signup'))

            try:
                user = auth.create_user(email=email, password=password)

                # After creating the user, send an email verification
                auth.generate_email_verification_link(email)

                flash("Successfully signed up! Please verify your email before logging in.")
                return redirect(url_for('login'))
            except FirebaseError:
                flash("Error creating user")
                return redirect(url_for('signup'))
        return render_template('signup.html')


@app.route('/index', methods=['GET', 'POST'])
def index():
        if 'uid' in session:
            passwords_ref = db.reference('passwords').child(session['uid'])
            passwords = passwords_ref.get() or {}
            return render_template('index.html', passwords=passwords)
        else:
            flash("Please login to access this page")
            return redirect(url_for('login'))

@app.route('/add_password', methods=['POST'])
def add_password():
        if 'uid' in session:
            site = request.form['site']
            username = request.form['username']
            password = request.form['password']

            passwords_ref = db.reference('passwords').child(session['uid'])
            passwords_ref.child(site).set({
                'username': username,
                'password': password
            })
            flash("Password added successfully!")
        else:
            flash("Please login to access this feature")
        return redirect(url_for('index'))

@app.route('/search_password', methods=['POST'])
def search_password():
        if 'uid' in session:
            search_term = request.form['search'].lower()

            passwords_ref = db.reference('passwords').child(session['uid'])
            all_passwords = passwords_ref.get() or {}

            searched_passwords = {key: val for key, val in all_passwords.items() if search_term in val['site'].lower()}
            return render_template('index.html', passwords=searched_passwords)
        else:
            flash("Please login to access this feature")
            return redirect(url_for('index'))

@app.route('/delete_password/<site>', methods=['POST'])
def delete_password(site):
        if 'uid' in session:
            passwords_ref = db.reference('passwords').child(session['uid']).child(site)
            passwords_ref.delete()
            flash("Password deleted successfully!")
        else:
            flash("Please login to access this feature")
        return redirect(url_for('index'))

@app.route('/login_google', methods=['POST'])
def login_google():
        id_token = request.form['idtoken']
        try:
            # Verify the token
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            session['uid'] = uid
            return jsonify({'status': 'success'}), 200
        except ValueError:
            # Token is invalid
            return jsonify({'status': 'token invalid'}), 401

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
        if request.method == 'POST':
            email = request.form['email']
            try:
                auth.send_password_reset_email(email)
                flash('Password reset email sent. Check your inbox.')
                return redirect(url_for('login'))
            except FirebaseError:
                flash('Error sending password reset email.')
                return redirect(url_for('forgot_password'))

        return render_template('forgot_password.html')

@app.route('/logout')
def logout():
        session.pop('uid', None)
        return redirect(url_for('login'))


@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')


if __name__ == "__main__":
      app.run(host= '0.0.0.0', port= 8080)
