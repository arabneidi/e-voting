from datetime import date

def calculate_age(birthdate):
    """Calculate age based on the given birthdate."""
    today = date.today()
    return today.year - birthdate.year - ((today.month, today.day) < (birthdate.month, birthdate.day))
