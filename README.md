# SentinelWEB

## Title
SentinelWEB: A Comprehensive Cybersecurity Toolkit
### By: HAFEEZUL DEEN S

## Problem Statement
In today's digital age, users face numerous cybersecurity threats, including weak passwords and phishing attacks. Many individuals and small businesses lack the necessary tools to protect their sensitive information and assess their cybersecurity posture. This project aims to provide a user-friendly platform for generating strong passwords, analyzing password strength, and detecting potential phishing attempts in email content and personal text encryption tool.

## About This Project
SentinelWEB is a cybersecurity toolkit that includes 4 main features:
1. **Password Creator AI**: Generates strong passwords based on user-defined criteria, helping users create secure passwords that are harder to guess.
2. **Password Strength Analyzer**: Evaluates the strength of user-entered passwords and provides feedback on how to improve them.
3. **Phishing Email Detector**: Analyzes email content for common phishing keywords, alerting users to potential scams.
4. **Personal Text Encryption Tool**: A Personal Text Encryption Tool that securely converts your messages into encrypted code and decrypts them back using a unique secret key for personal desired own purposes with only needed persons we communicate the confiedntial informations.

Now its an Prototype. so, it only have 4 types of Tools only .

The project is built using Flask, a lightweight web framework, making it accessible and easy to deploy.

## Program
*Pass_crtr.html*
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Creator AI</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: white; /* Changed to white */
            color: black; /* Changed to black */
        }

        h1, h2 {
            text-align: center;
            color: black; /* Changed heading text to black */
        }

        .container {
            width: 50%;
            margin: 0 auto;
        }

        .box {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            background-color: #f9f9f9; /* Changed background to light gray */
        }

        input[type="number"],
        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
            background-color: white; /* Changed input background to white */
            color: black; /* Changed text color in input to black */
        }

        button {
            padding: 10px 20px;
            background-color: #4CAF50; /* Green color */
            color: white; /* White text */
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        button:hover {
            background-color: #45a049; /* Darker green on hover */
        }

        .info-box {
            background-color: #f0f0f5; /* Light gray for info box */
            border-left: 6px solid #2196F3; /* Blue color for border */
            padding: 10px;
            margin-top: 15px;
        }

        h2 {
            color: #4CAF50; /* Green color for subheadings */
        }

        a {
            position: absolute;
            top: 10px;
            left: 10px;
            padding: 10px 15px;
            background-color: black; /* Changed background to black */
            color: white; /* Changed text color to white */
            text-decoration: none; /* No underline */
            border-radius: 5px; /* Rounded corners */
        }
    </style>
</head>
<body>
    <a href="/">Home</a>
    
    <div class="container">
        <h1>Password Creator AI</h1>
        <form method="POST">
            <div class="box">
                <label for="length">Password Length:</label>
                <input type="number" id="length" name="length" required>

                <label for="include_numbers">Include Numbers:</label>
                <input type="checkbox" id="include_numbers" name="include_numbers" checked>

                <label for="include_symbols">Include Symbols:</label>
                <input type="checkbox" id="include_symbols" name="include_symbols" checked>

                <label for="custom_input">Your unforgettable number or name or symbol (optional):</label>
                <input type="text" id="custom_input" name="custom_input">

                <button type="submit">Generate Password</button>
            </div>
        </form>
        
        {% if password %}
            <div class="box">
                <h2>Generated Password: {{ password }}</h2>
            </div>
        {% endif %}
    </div>
</body>
</html>

```

*Pass_anzlr.html*
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Strength Analyzer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #fff; /* Changed to white */
            color: #000; /* Changed to black */
        }

        h1, h2 {
            text-align: center;
            color: #000; /* Ensure heading text is black */
        }

        .container {
            width: 50%;
            margin: 0 auto;
        }

        .box {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #000; /* Changed to black */
            border-radius: 5px;
            background-color: #f9f9f9; /* Changed to light gray */
        }

        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #000; /* Changed to black */
            border-radius: 5px;
            background-color: #fff; /* Changed to white */
            color: #000; /* Changed text color in input to black */
        }

        button {
            padding: 10px 20px;
            background-color: #4CAF50; /* Green color */
            color: white; /* Changed text color to white */
            border: none;
            border-radius: 5px;
            cursor: pointer;
        }

        button:hover {
            background-color: #45a049; /* Darker green on hover */
        }

        a {
            position: absolute;
            top: 10px;
            left: 10px;
            padding: 10px 15px;
            background-color: black; /* Changed background to black */
            color: white; /* Changed text color to white */
            text-decoration: none; /* No underline */
            border-radius: 5px; /* Rounded corners */
        }
    </style>
</head>
<body>
    <a href="/">Home</a>
    
    <div class="container">
        <h1>Password Strength Analyzer</h1>
        <form method="POST">
            <div class="box">
                <label for="password">Enter your password:</label>
                <input type="text" id="password" name="password" required>
                <button type="submit">Analyze Password</button>
            </div>
        </form>

        {% if strength %}
            <div class="box">
                <h2>Password Strength: {{ strength }}</h2>
            </div>
        {% endif %}
    </div>
</body>
</html>

```

*Phishing_dctr.html*
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Phishing Email Detector</title>
    <link rel="stylesheet" href="/static/style.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: white; /* Changed to white */
            color: black; /* Changed to black */
        }
        h1 {
            text-align: center;
            color: black; /* Changed heading text to black */
        }
        .container {
            width: 50%;
            margin: 0 auto;
        }
        input[type="text"],
        textarea {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 5px;
            background-color: white; /* Changed background to white */
            color: black; /* Changed text color in input to black */
        }
        button {
            padding: 10px 20px;
            background-color: #4CAF50; /* Green color */
            color: white; /* White text */
            border: none;
            border-radius: 5px;
            cursor: pointer;
            display: block; /* Ensure button takes full width */
            margin: 0 auto; /* Center the button */
        }
        button:hover {
            background-color: #45a049; /* Darker green on hover */
        }
        a {
            position: absolute;
            top: 10px;
            left: 10px;
            padding: 10px 15px;
            background-color: black; /* Changed background to black */
            color: white; /* Changed text color to white */
            text-decoration: none; /* No underline */
            border-radius: 5px; /* Rounded corners */
        }
        .warning {
            color: rgb(0, 0, 0); /* Changed warning text to black */
            font-weight: bold; /* Make warning bold */
        }
        .note {
            background-color: #f9f9f9; /* Light gray background for the note */
            padding: 10px;
            border: 1px solid #ccc;
            border-radius: 5px;
            margin: 10px 0; /* Add some margin above the note */
        }
    </style>
</head>
<body>
    <a href="/">Home</a>
    <div class="container">
        <h1>Phishing Email Detector</h1>
        <form method="POST">
            <label for="email_content">Paste your email content here:</label>
            <textarea id="email_content" name="email_content" rows="10" cols="50" required></textarea>
            <div class="note">Note: Only paste the body content of the email.</div>
            <button type="submit">Analyze Email</button>
        </form>
        {% if result %}
            <h2>Analysis Result: <span class="warning">{{ result }}</span></h2>
        {% endif %}
    </div>
</body>
</html>

```

*app.py*
```
from flask import Flask, render_template, request, jsonify
import random
import string
import re
import datetime
from encryption_tool.encryption_tool import encrypt_message, decrypt_message, generate_key

app = Flask(__name__)

# Home route
@app.route('/')
def home():
    return render_template('index.html')  # Link to your main home page

# Password Creator AI route
@app.route('/password_creator', methods=['GET', 'POST'])
def password_creator():
    password = None
    if request.method == 'POST':
        length = int(request.form['length'])
        include_symbols = 'include_symbols' in request.form
        include_numbers = 'include_numbers' in request.form
        custom_input = request.form['custom_input']

        password = generate_password(length, include_symbols, include_numbers, custom_input)
    return render_template('password_creator.html', password=password)

def generate_password(length, include_symbols, include_numbers, custom_input):
    characters = string.ascii_letters
    if include_symbols:
        characters += string.punctuation
    if include_numbers:
        characters += string.digits
    
    if custom_input:
        password = ''.join(random.choice(characters) for _ in range(length - len(custom_input))) + custom_input
    else:
        password = ''.join(random.choice(characters) for _ in range(length))
    
    return ''.join(random.sample(password, len(password)))  # Shuffle the password

# Password Strength Analyzer route
@app.route('/password_analyzer', methods=['GET', 'POST'])
def password_analyzer():
    strength = None
    if request.method == 'POST':
        password = request.form['password']
        strength = check_password_strength(password)
    return render_template('password_analyzer.html', strength=strength)

def check_password_strength(password):
    length = len(password)
    if length < 6:
        return 'Weak'
    
    has_letters = re.search(r"[A-Za-z]", password)
    has_numbers = re.search(r"[0-9]", password)
    has_symbols = re.search(r"[@$!%*#?&]", password)

    if has_letters and has_numbers and has_symbols and length >= 12:
        return 'Strong'
    elif (has_letters and has_numbers) or (has_letters and has_symbols) or (has_numbers and has_symbols):
        return 'Medium'
    else:
        return 'Weak'

# Encryption Tool routes
@app.route('/generate-key')
def generate_key_route():
    key = generate_key()
    return f"Key generated and saved as secret.key: {key}"

@app.route('/encrypt', methods=['POST'])
def encrypt_route():
    message = request.form.get('message')
    if not message:
        return "Please provide a message to encrypt.", 400  # Handle missing message error
    encrypted = encrypt_message(message)
    # Highlight the `b' '` to wrap around the encrypted message
    return f"Encrypted Message: <div style='color:green;'>b'{encrypted.decode()}'</div>"

@app.route('/decrypt', methods=['POST'])
def decrypt_route():
    encrypted_message = request.form.get('encrypted_message')
    
    # Strip unnecessary characters if present
    if encrypted_message.startswith("b'") and encrypted_message.endswith("'"):
        encrypted_message = encrypted_message[2:-1]
    
    try:
        decrypted = decrypt_message(encrypted_message.encode())
        return f"Decrypted Message: <div style='color:blue;'>{decrypted}</div>"
    except Exception as e:
        return f"An error occurred during decryption: {str(e)}", 400

@app.route('/encryption_tool', methods=['GET', 'POST'])
def encryption_tool():
    encrypted_message = None
    decrypted_message = None
    error_message = None
    
    if request.method == 'POST':
        if 'encrypt' in request.form:
            message = request.form.get('message')
            if message:
                encrypted_message = encrypt_message(message)
                # Show encrypted message wrapped in `b' '`
                encrypted_message = f"b'{encrypted_message.decode()}'"
            else:
                error_message = "Please provide a message to encrypt."
        elif 'decrypt' in request.form:
            encrypted_message = request.form.get('encrypted_message')
            if encrypted_message:
                try:
                    # Strip and decode before decrypting
                    if encrypted_message.startswith("b'") and encrypted_message.endswith("'"):
                        encrypted_message = encrypted_message[2:-1]
                    decrypted_message = decrypt_message(encrypted_message.encode())
                except Exception as e:
                    error_message = f"Decryption failed: {str(e)}"
            else:
                error_message = "Please provide an encrypted message to decrypt."
    
    return render_template('encryption_tool.html', 
                           encrypted_message=encrypted_message, 
                           decrypted_message=decrypted_message,
                           error_message=error_message)

def detect_phishing(email_content):
    # Simple keyword detection logic (you can expand this)
    phishing_keywords = ['urgent', 'password', 'confirm', 'account']
    for keyword in phishing_keywords:
        if keyword in email_content.lower():
            return "Warning: This email may be a phishing attempt."
    return "This email appears to be safe."

@app.route('/phishing_detector', methods=['GET', 'POST'])
def phishing_detector():
    result = None
    if request.method == 'POST':
        email_content = request.form['email_content']
        result = detect_phishing(email_content)
    return render_template('phishing_detector.html', result=result)



# Global list to store malicious attempts
honeypot_logs = []

# Secret password for accessing honeypot logs
ADMIN_PASSWORD = 'HAFEEX'  # Change this to your desired password

# Route for Honeypot
@app.route('/honeypot', methods=['GET', 'POST'])
def honeypot():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Log malicious attempt
        honeypot_logs.append({
            "username": username,
            "password": password,
            "ip_address": ip_address,
            "timestamp": timestamp
        })

        # Redirect to a fake "error" page or refresh honeypot
        return render_template('honeypot.html', message="Invalid credentials! Please try again.")

    return render_template('honeypot.html', message=None)

# Route to view logs with authentication
@app.route('/honeypot_logs', methods=['GET', 'POST'])
def view_honeypot_logs():
    if request.method == 'POST':
        entered_password = request.form.get('password')
        if entered_password == ADMIN_PASSWORD:
            return render_template('honeypot_logs.html', logs=honeypot_logs)
        else:
            return "Unauthorized access. Wrong password.", 403

    # Show the login form for admin access
    return render_template('honeypot_login.html')







if __name__ == '__main__':
    app.run(debug=True, port=5001)

```


### Programming Topic: Web Development with Flask
Flask is a lightweight web framework for Python that allows for rapid development of web applications. It provides the tools and libraries necessary to build web services, manage user requests, and render HTML templates.

### Usage of Flask in Our Project
1. **Routing**: Flask handles routing with decorators to define URL endpoints for different functionalities (e.g., password generation, password analysis, phishing detection).
  
2. **Templates**: Using Jinja2 templating engine, Flask renders HTML pages dynamically based on user input and backend logic.

3. **Form Handling**: Flask's request object allows for easy handling of form submissions, making it simple to retrieve user data for processing (e.g., generating passwords, analyzing password strength).

4. **Error Handling**: Flask enables the handling of errors and exceptions gracefully, improving user experience by providing informative feedback.

5. **Development Server**: Flask includes a built-in development server, making it easy to test and debug your application during development.

This combination of features makes Flask a popular choice for developing web applications in Python, especially for projects that require a straightforward setup and quick iteration.


## Wow Factors
- **User-Friendly Interface**: The application is designed for ease of use, allowing individuals of all technical levels to navigate effortlessly.
- **Customizable Password Generation**: Users can specify their password requirements, ensuring their generated passwords meet specific security needs.
- **Real-Time Feedback**: Instant results for password strength and phishing detection enhance user experience and security awareness.
- **Versatile Cybersecurity Tools**: The project will incorporate a variety of cybersecurity tools, including:
  1. Password Strength Analyzer
  2. Phishing Email Detector
  3. Secure Password Generator
  4. Data Encryption Tool
  5. Malware Scanner
  6. Vulnerability Assessment Tool
  7. Network Security Analyzer
  8. Firewall Configuration Advisor
  9. Secure File Sharing Utility
  10. Incident Response Toolkit
etc.........

In the future, we plan to implement 100+ cybersecurity tools, transforming the platform into a comprehensive threat intelligence system that leverages AI for advanced security solutions. This will empower users with innovative tools to proactively manage their cybersecurity needs and adapt to the ever-evolving threat landscape.


## Future AI Enhancements
In the future, we plan to implement 100+ cybersecurity tools designed to create a comprehensive threat intelligence platform. These enhancements will include:
- **Advanced Threat Detection**: Utilizing machine learning algorithms to identify and respond to emerging threats in real-time, providing users with up-to-date security measures.
- **Personalized Security Insights**: Offering users tailored recommendations based on their usage patterns and threat landscape, enabling proactive risk management.
- **Automated Incident Response**: Developing features that automatically respond to potential security incidents, reducing response times and minimizing damage.
- **Enhanced Phishing Detection**: Improving phishing detection capabilities by analyzing user behavior and adapting to new tactics employed by cybercriminals.
- **Vulnerability Management**: Providing automated tools to identify and remediate vulnerabilities in user systems, ensuring ongoing protection against attacks.

Our commitment to evolving the platform into a leading threat intelligence and AI-driven security solution will empower users to stay ahead of cyber threats and maintain a secure digital presence.


## Output Screenshots
![image](https://github.com/user-attachments/assets/43339a6d-b5c0-4e26-8a09-92950662904b)
### *Home*


![image](https://github.com/user-attachments/assets/49dff06e-ab8a-4fb8-9ad7-5b7ee2ae8209)
### *Password Creator Interface*


![image](https://github.com/user-attachments/assets/f9766210-f166-443a-96a5-0b6a2992898e)
### *Password Strength Analysis Result*


![image](https://github.com/user-attachments/assets/ab50ebe0-200f-449f-b060-af38a5c9a54f)
<img width="1919" height="788" alt="Screenshot 2025-10-22 120044" src="https://github.com/user-attachments/assets/85d7d429-29be-4cba-875c-3e482cd1c99f" />
### *Phishing Email Detection Result*


<img width="1897" height="827" alt="Screenshot 2025-10-22 114931" src="https://github.com/user-attachments/assets/f3a2920e-f9e3-4397-8487-d0997b8f6d67" />
<img width="1919" height="458" alt="Screenshot 2025-10-22 115018" src="https://github.com/user-attachments/assets/c7cde2cf-5149-44c9-acd5-e752a744d21a" />
### *Personal Text Encryption Tool*

## Installation
To run the project locally, follow these steps:
1. Clone the repository: `git clone https://github.com/yourusername/SentinelWEB.git`
2. Navigate to the project directory: `cd SentinelWEB`
3. Install the required packages: `pip install -r requirements.txt`
4. Run the application: `python app.py`
5. Open your web browser and navigate to `http://127.0.0.1:5001`


## Acknowledgments
- Thanks to Flask for providing an easy-to-use web framework.
- Special thanks to the contributors and supporters of this project.

### Copyrights Owned By Hafeezul Deen S
