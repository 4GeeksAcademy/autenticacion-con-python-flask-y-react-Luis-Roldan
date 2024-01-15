"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, send_from_directory
from flask_migrate import Migrate
from flask_swagger import swagger
from api.utils import APIException, generate_sitemap
from api.models import User, db
from api.routes import api
from api.admin import setup_admin
from api.commands import setup_commands
from bcrypt import gensalt
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required

# from models import Person

ENV = "development" if os.getenv("FLASK_DEBUG") == "1" else "production"
static_file_dir = os.path.join(os.path.dirname(
    os.path.realpath(__file__)), '../public/')
app = Flask(__name__)
app.url_map.strict_slashes = False

#Flask JWT extended
app.config["JWT_SECRET_KEY"] = os.getenv("FLASK_JWT_SECRET")
jwt = JWTManager(app)

# database condiguration
db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace(
        "postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/test.db"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
MIGRATE = Migrate(app, db, compare_type=True)
db.init_app(app)

# add the admin
setup_admin(app)

# add the admin
setup_commands(app)

# Add all endpoints form the API with a "api" prefix
app.register_blueprint(api, url_prefix='/api')

# Handle/serialize errors like a JSON object


@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints


@app.route('/')
def sitemap():
    if ENV == "development":
        return generate_sitemap(app)
    return send_from_directory(static_file_dir, 'index.html')


@app.route("/user", methods=["POST"])
def handle_register():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    #creacion de salt   
    salt = str(gensalt(), encoding='utf-8')
    print(salt)
    print(type(salt))
    #hashed password
    hashed_password = str(generate_password_hash(password + salt), encoding='utf-8')
    print(hashed_password)
    #crear usuario
    new_user = User(
        email = email,
        hashed_password =  hashed_password,
        salt = salt )
    print(new_user)
    #guardar en db
    try:
        db.session.add(new_user)
        db.session.commit()
    except Exception as error:
        db.session.rollback()
        return jsonify({
            "message": "DB error"

        }), 500
    return "", 201
    
@app.route("/token", methods=["POST"])
def handle_login():
    data = request.json
    email = data.get("email")
    password = data.get("password")            
    #traer al usuario al que pertenece correo
    user = User.query.filter_by(email=email).one_or_none()
    if user is None:
        return jsonify({
            "message": "user does not exist"
        }), 404
    #verificar si contrasena es correcta
    password_is_valid = check_password_hash(
        user.hashed_password,
        password + user.salt
    )
    #crear token 
    token = create_access_token(identity=user.id)
    return jsonify({"token": token})

@app.route("/user")
@jwt_required()
def get_user(id):
    id = get_jwt_identity()
    user = User.query.get(id)
    return jsonify(user.serialize()), 200

# any other endpoint will try to serve it like a static file


@app.route('/<path:path>', methods=['GET'])
def serve_any_other_file(path):
    if not os.path.isfile(os.path.join(static_file_dir, path)):
        path = 'index.html'
    response = send_from_directory(static_file_dir, path)
    response.cache_control.max_age = 0  # avoid cache memory
    return response


# this only runs if `$ python src/main.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3001))
    app.run(host='0.0.0.0', port=PORT, debug=True)
