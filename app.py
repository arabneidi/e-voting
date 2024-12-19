from flask import Flask
from flask_cors import CORS
import pymysql
from dotenv import load_dotenv

# Load environment variables
load_dotenv("D:/aws voting/backend/.env")

from config import Config
from utils.election_data_utils import initialize_election_data_on_startup
from extensions import db, migrate, session

# Import blueprints
from routes.voting_routes import voter_bp
from routes.admin_routes import admin_bp
from routes.blockchain_routes import blockchain_bp
from routes.auth_routes import auth_bp
from routes.utility_routes import utility_bp
from routes.dialogflow_routes import dialogflow_bp

pymysql.install_as_MySQLdb()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object(Config)

# Initialize extensions
CORS(app, resources={r"/*": {"origins": app.config['CORS_ORIGINS']}})
session.init_app(app)
db.init_app(app)
migrate.init_app(app, db)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Database tables created successfully.")
        initialize_election_data_on_startup()

    # Register blueprints
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(voter_bp, url_prefix='/voter')
    app.register_blueprint(blockchain_bp, url_prefix='/blockchain')
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(utility_bp)
    app.register_blueprint(dialogflow_bp, url_prefix='/dialogflow')

    app.run(host='0.0.0.0', port=5000, debug=True)  # Update here

