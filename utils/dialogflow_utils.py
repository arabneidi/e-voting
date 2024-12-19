import google.cloud.dialogflow_v2 as dialogflow
from flask import current_app


def get_dialogflow_response(session_id, user_message, language_code="en"):
    """Send a message to Dialogflow and get the response."""
    project_id = current_app.config['PROJECT_ID']
    session_client = dialogflow.SessionsClient()
    session = session_client.session_path(project_id, session_id)

    text_input = dialogflow.TextInput(text=user_message, language_code=language_code)
    query_input = dialogflow.QueryInput(text=text_input)
    response = session_client.detect_intent(session=session, query_input=query_input)

    return response.query_result.fulfillment_text
