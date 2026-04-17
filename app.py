import os
import cv2
import numpy as np
import pandas as pd
from PIL import Image
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, flash, redirect, url_for, jsonify, session
from Database import *
import pickle
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

# Secret key for session management
app.secret_key = 'super_secret_key'

# Allowed file extensions
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Reverse mapping dictionary to decode predicted class
class_mapping_reverse = {
    0: 'BENIGN',
    1: 'Bot',
    2: 'DDoS',
    3: 'DoS GoldenEye',
    4: 'DoS Hulk',
    5: 'DoS Slowhttptest',
    6: 'DoS slowloris',
    7: 'FTP-Patator',
    8: 'Heartbleed',
    9: 'Infiltration',
    10: 'PortScan',
    11: 'SSH-Patator',
    12: 'Web Attack - Brute Force',
    13: 'Web Attack - SQL Injection',
    14: 'Web Attack - XSS'
}

# Define the order and types of features manually
feature_order = [
    ' Fwd Packet Length Mean',
    ' Fwd Packet Length Max',
    ' Avg Fwd Segment Size',
    ' Subflow Fwd Bytes',
    'Total Length of Fwd Packets',
    ' Flow IAT Max',
    ' Average Packet Size',
    ' Bwd Packet Length Std',
    ' Flow Duration',
    ' Avg Bwd Segment Size',
    ' Bwd Packets/s', 
    ' Packet Length Mean',
    'Init_Win_bytes_forward',
    ' Init_Win_bytes_backward',
    ' Packet Length Std',
    ' Fwd IAT Max',
    ' Fwd Packet Length Std',
    ' Packet Length Variance',
    ' Total Length of Bwd Packets',
    ' Flow Packets/s'
]

# Load the trained model
loaded_model = pickle.load(open("C:/Users/saish/OneDrive/Desktop/models/rf_classifier.pkl", 'rb'))

# Email function
def send_email(to_email, subject, body):
    try:
        # SMTP configuration
        sender_email = "@gmail.com"  # Replace with your email
        sender_password = "vqqt jaeg jkkl zusf"  # Replace with your app-specific password
        smtp_server = "smtp.gmail.com"
        smtp_port = 587

        # Create email
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = to_email
        message["Subject"] = subject
        message.attach(MIMEText(body, "plain"))

        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)
            print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

# Helper function to fetch user email
def fetch_user_email():
    if 'user_email' in session:
        return session['user_email']
    else:
        raise Exception("User email not found in session")

# Routes
@app.route("/")
def index():
    return render_template("index.html", xx=-1)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html', xx=-1)

@app.route('/index')
def index1():
    return render_template('index.html')

@app.route('/home')
def home():
    return render_template('index.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/register', methods=['POST', 'GET'])
def registration():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        mobile = 0
        InsertData(username, email, password, mobile)
        return render_template('login.html')
    return render_template('register.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        email = request.form['email']
        passw = request.form['password']
        resp = read_cred(email, passw)
        if resp is not None:
            session['user_email'] = email
            return redirect("/dashboard")
        else:
            message = "Username and/or Password incorrect.\nYou have not registered yet.\nGo to Register page and do Registration."
            flash(message)
            return redirect("/login")
    return render_template('login.html')

@app.route("/predict", methods=["POST"])
def predict():
    try:
        # Collect input data from the form
        user_input = {}
        for column in feature_order:
            value = request.form.get(column)
            try:
                user_input[column] = float(value) if value is not None else 0.0  # Convert to float, default to 0.0
            except ValueError:
                user_input[column] = 0.0  # Default to 0.0 for invalid entries

        # Create DataFrame
        user_data = pd.DataFrame([user_input])

        # Check for NaN or invalid values and replace with a default
        user_data = user_data.replace([np.inf, -np.inf, np.nan], 0.0)

        # Ensure all columns are present in the correct order
        user_data = user_data[feature_order]

        # Make prediction
        prediction = loaded_model.predict(user_data)
        decoded_class = class_mapping_reverse.get(prediction[0], 'Unknown')

        # Mocked email retrieval; replace with session-based email
        email = fetch_user_email()  # Replace with user's email from session or database

        # Send email with results
        subject = "Prediction Results"
        body = f"Hello,\n\nThe predicted class for your input is: {decoded_class}.\n\nThank you for using our service!"
        send_email(email, subject, body)

        return render_template("dashboard.html", attack=decoded_class)
    except Exception as e:
        return jsonify({"error": str(e)})



@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('upload.html', error='No file part')

        file = request.files['file']

        if file.filename == '':
            return render_template('upload.html', error='No selected file')

        try:
            df = pd.read_csv(file)
            predictions = loaded_model.predict(df)
            class_names = [class_mapping_reverse.get(prediction, 'Unknown') for prediction in predictions]
            predictions = predictions.astype(np.int64).tolist()

            response = [{'sr_no': i + 1, 'class_index': prediction, 'class_name': class_name} for i, (prediction, class_name) in enumerate(zip(predictions, class_names))]

            email = fetch_user_email()
            subject = "Batch Prediction Results"
            body = f"Hello,\n\nHere are the batch prediction results:\n\n{response}\n\nThank you for using our service!"
            send_email(email, subject, body)

            return render_template('upload.html', predictions=response)
        except Exception as e:
            return render_template('upload.html', error=str(e))

    return render_template('upload.html', error=None)

if __name__ == "__main__":
    app.run(debug=True)
