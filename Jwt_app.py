# flask imports
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid # for public id
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta
from functools import wraps
import secrets
import logging #mointoring purpose



# creates Flask object
app = Flask(__name__)
# configuration
app.config['SECRET_KEY'] = secrets.token_hex(16)
# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:2630@localhost/flask'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)




# Database ORMs
class TableAmrith(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    password = db.Column(db.String(255))




# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')

        if not token:    
            return jsonify({'message': 'Token is missing !!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = TableAmrith.query\
                .filter_by(public_id=data['public_id'])\
                .first()
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401

        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid Token'}), 401

        except Exception as e:
            logging.error(f"Error decoding token: {str(e)}")
            return jsonify({'message': 'Token is invalid !!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated






@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    users = TableAmrith.query.all()
    output = []
    for user in users:
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email,
            'id': user.id
        })

    return jsonify({'users': output})





# route for logging user in
@app.route('/login', methods=['POST'])
def login():
    auth = request.form

    if not auth or not auth.get('email') or not auth.get('password'):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm="Login required !!"'}
        )

    user = TableAmrith.query \
        .filter_by(email=auth.get('email')) \
        .first()

    if not user or not check_password_hash(user.password, auth.get('password')):
        return make_response(
            'Could not verify',
            401,
            {'WWW-Authenticate': 'Basic realm="Invalid credentials !!"'}
        )

    token = jwt.encode({
        'public_id': user.public_id,
        'exp': datetime.utcnow() + timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})





@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form

    # gets name, email, and password
    name, email, password = data.get('name'), data.get('email'), data.get('password')

    # checking for missing form data
    if not name or not email or not password:
        return make_response('Missing required data. Please provide name, email, and password.', 400)

    # checking for existing user
    user = TableAmrith.query\
        .filter_by(email=email)\
        .first()

    if not user:
        # database ORM object
        user = TableAmrith(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return make_response('Successfully registered.', 201)
    else:
        # returns 202 if user already exists
        return make_response('User already exists. Please Log in.', 202)




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(debug=True)
