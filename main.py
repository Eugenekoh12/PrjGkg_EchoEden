#Glenys Password Hashing
from flask import Flask, request, jsonify
import bcrypt

app = Flask(__name__)
@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']

    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    return jsonify({'message': 'User registered successfully'})


@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password):
        return jsonify({'message': 'Login successful'})
    else:
        return jsonify({'message': 'Invalid username or password'}), 401

if __name__ == '__main__':
    app.run(debug=True)
