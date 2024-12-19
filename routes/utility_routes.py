from flask import Blueprint

# Initialize a Blueprint for utility routes
utility_bp = Blueprint('utility', __name__)

# Health check endpoint to confirm server status
@utility_bp.route('/health', methods=['GET'])
def health_check():
    return 'OK', 200
