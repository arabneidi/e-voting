# Import necessary modules from Flask and custom utilities
from flask import Blueprint, request, jsonify, current_app  # Flask components to manage routes and responses
from utils.dialogflow_utils import get_dialogflow_response  # Utility function to handle Dialogflow responses

# Initialize a Blueprint for Dialogflow routes, enabling modular organization within the app
dialogflow_bp = Blueprint('dialogflow', __name__)

# Define a route for handling POST requests at '/chat' for Dialogflow interactions
@dialogflow_bp.route('/chat', methods=['POST'])
def chat():
    # Get JSON data from the request, expecting a 'message' key for user input
    data = request.get_json()
    user_message = data.get("message")

    # Define a unique session ID for Dialogflow session tracking
    session_id = "unique-session-id"  # Replace with a truly unique ID per user session if needed

    try:
        # Retrieve a response from Dialogflow using the user message
        bot_response = get_dialogflow_response(session_id, user_message)
        # Return the bot's response as JSON to the frontend
        return jsonify({"response": bot_response})
    except Exception as e:
        # In case of an error, return an error message with a 500 status code
        return jsonify({"error": str(e)}), 500

