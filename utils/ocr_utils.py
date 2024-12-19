import re
from google.cloud import vision

def extract_id_card_number(id_card_file):
    """Extracts the passport number from the uploaded image using Google Vision API."""
    client = vision.ImageAnnotatorClient()

    # Read the image file content
    content = id_card_file.read()

    # Construct the image object for the Vision API
    image = vision.Image(content=content)

    # Call the text detection API
    response = client.text_detection(image=image)
    texts = response.text_annotations

    # Check if texts were detected
    if not texts:
        raise ValueError("No text detected in the image.")

    # The first result is typically the largest block of text
    extracted_text = texts[0].description

    # Look for the passport number using regex (searching for "Passport No:")
    passport_match = re.search(r'Passport No:\s*(\d+)', extracted_text)

    if not passport_match:
        raise ValueError("Passport number not found in the extracted text.")

    # Return the passport number
    return passport_match.group(1)
