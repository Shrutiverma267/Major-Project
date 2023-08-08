from flask import Flask,session,flash,redirect,render_template,url_for, request
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from sqlalchemy import engine
from database import User
import tensorflow as tf
from joblib import load
import pandas as pd 
import numpy as np
import re

def load_model():
    model = tf.keras.models.load_model('ann_fraud_detection.h5')
    return model

def load_preprocessor():
    p = load('ann_fraud_detection_preprocessor.jb')
    return p

def validate_email(email):  
    regex = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if(re.search(regex,email)):  
        return True 
    return False

def predict_fraud(model, data):

    data = p.transform(data)
    prediction = model.predict(data)
    return {
        'prediction': prediction[0][0] > 0.5,
        'confidence': int(prediction[0][0] * 100 if prediction[0][0] > 0.5 else (1 - prediction[0][0]) * 100)
    }

model = load_model()
p = load_preprocessor()

app = Flask(__name__)
app.secret_key = "the basics of life with python"

def get_db():
    engine = create_engine('sqlite:///database.sqlite')
    Session = scoped_session(sessionmaker(bind=engine))
    return Session()

@app.route('/', methods=['GET'])
def home():
    ttypes = ['PAYMENT', 'TRANSFER', 'CASH_OUT', 'DEBIT', 'CASH_IN']
    return render_template('index.html',title='Home',ttypes=ttypes)

@app.route('/detect', methods=['POST','GET'])
def detect():
    if not session.get('isauth',False):
        flash('You cannot predict before authenticating', 'danger')
        return redirect('/login')
    if request.method == 'POST':
        try:
            t_type = request.form.get('type')
            amount = request.form.get('amount')
            oldbalanceOrg = request.form.get('oldbalanceOrg')
            newbalanceOrig = request.form.get('newbalanceOrig')
            oldbalanceDest = request.form.get('oldbalanceDest')
            newbalanceDest = request.form.get('newbalanceDest')
            data = pd.DataFrame({
                'type': [t_type],
                'amount': [amount],
                'oldbalanceOrg': [oldbalanceOrg],
                'newbalanceOrig': [newbalanceOrig],
                'oldbalanceDest': [oldbalanceDest],
                'newbalanceDest': [newbalanceDest]
            })
            out = predict_fraud(model, data)
            flash('prediction successful','success')
            return render_template('result.html', out=out)
        except Exception as e:
            print(e)
            flash('something went wrong, please fill details correctly','danger')
            return redirect('/')
    flash('fill the form to predict','warning')
    return redirect('/')

@app.route('/login',methods=['GET','POST'])
def index():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if email and validate_email(email):
            if password and len(password)>=6:
                try:
                    sess = get_db()
                    print(email, password)
                    user = sess.query(User).filter_by(email=email,password=password).first()
                    print(user)
                    if user:
                        session['isauth'] = True
                        session['email'] = user.email
                        session['id'] = user.id
                        session['name'] = user.name
                        del sess
                        flash('login successfull','success')
                        return redirect('/')
                    else:
                        flash('email or password is wrong','danger')
                except Exception as e:
                    flash(e,'danger')
            else:
                flash('password is incorrect','danger')
        else:
            flash('email is invalid','danger')
    return render_template('login.html',title='login')

@app.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        cpassword = request.form.get('cpassword')
        if name and len(name) >= 3:
            if email and validate_email(email):
                if password and len(password)>=6:
                    if cpassword and cpassword == password:
                        try:
                            sess = get_db()
                            newuser = User(name=name,email=email,password=password)
                            sess.add(newuser)
                            sess.commit()
                            del sess
                            flash('registration successful','success')
                            return redirect('/login')
                        except Exception as e:
                            print(e)
                            flash('email account already exists','danger')
                    else:
                        flash('confirm password does not match','danger')
                else:
                    flash('password must be of 6 or more characters','danger')
            else:
                flash('invalid email','danger')
        else:
            flash('invalid name, must be 3 or more characters','danger')
    return render_template('signup.html',title='register')

@app.route('/about')
def about():
    return render_template('about.html',title='About Us')

@app.route('/logout')
def logout():
    if session.get('isauth'):
        session.clear()
        flash('you have been logged out','warning')
    return redirect('/')


if __name__ == "__main__":
    app.run(debug=True,threaded=True)
