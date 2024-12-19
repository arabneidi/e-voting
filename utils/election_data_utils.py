from flask import current_app
import pandas as pd


# Global variable to hold postal code to riding data
postal_code_to_riding = {}


# Global variable to hold election data in memory
election_data = {
    'federal': {},
    'provincial': {},
    'territorial': {}
}

def initialize_election_data_on_startup():
    filepath = current_app.config['ELECTION_DATA_PATH']  # Use config path
    try:
        load_election_data(filepath)
        print("Election data loaded on app start.")
    except Exception as e:
        print(f"Failed to load election data during app start: {e}")


def load_election_data(filepath):
    """Load election data from an Excel file."""
    global election_data, postal_code_to_riding
    df = pd.read_excel(filepath, sheet_name=None)

    # Check required sheets exist
    required_sheets = ['Federal', 'Provincial', 'Territorial', 'Riding']
    for sheet in required_sheets:
        if sheet not in df:
            raise ValueError(f"Missing required sheet: {sheet}")

    # Store Federal sheet data
    federal_df = df['Federal']
    election_data['federal'] = federal_df.groupby('Riding Code').apply(lambda x: x.to_dict(orient='records')).to_dict()

    # Store Provincial sheet data
    provincial_df = df['Provincial']
    election_data['provincial'] = provincial_df.groupby('Riding Code').apply(lambda x: x.to_dict(orient='records')).to_dict()

    # Store Territorial sheet data
    territorial_df = df['Territorial']
    election_data['territorial'] = territorial_df.groupby('Riding Code').apply(lambda x: x.to_dict(orient='records')).to_dict()

    # Store Riding sheet data to map postal codes to ridings
    riding_df = df['Riding']
    postal_code_to_riding = riding_df.set_index('PostalCode').T.to_dict()

    return postal_code_to_riding  # Returning this mapping for use in postal code lookup

def get_riding_by_postal_code(postal_code):
    """Retrieve riding information based on the postal code."""
    global postal_code_to_riding

    # Convert postal code to uppercase for consistency
    postal_code = postal_code.upper()

    # Look up the riding using the postal code
    riding_info = postal_code_to_riding.get(postal_code)

    if not riding_info:
        print(f"No riding found for postal code: {postal_code}")
        return None

    # Return the riding code (Federal/Provincial/Territorial based on settings)
    return riding_info['RidingCode']


def parse_election_data(filepath):
    """Parse election data and verify required columns."""
    df = pd.read_excel(filepath, sheet_name=None)

    required_sheets = {
        'Federal': ['Riding Code', 'Candidate Name', 'Candidate Code', 'Candidate Party'],
        'Provincial': ['Province', 'Riding Code', 'Candidate Name', 'Candidate Code', 'Candidate Party'],
        'Territorial': ['Territory', 'Riding Code', 'Candidate Name', 'Candidate Code', 'Candidate Party']
    }

    missing_sheets = [sheet for sheet in required_sheets if sheet not in df]
    if missing_sheets:
        raise ValueError(f"Missing required sheet(s): {', '.join(missing_sheets)}")

    # Verify required columns
    for sheet, columns in required_sheets.items():
        if not all(col in df[sheet].columns for col in columns):
            missing_cols = [col for col in columns if col not in df[sheet].columns]
            raise ValueError(f"Missing required column(s): {', '.join(missing_cols)} in {sheet} sheet")

    # Get unique provinces and territories for frontend dropdowns
    provinces = df['Provincial']['Province'].unique().tolist() if 'Provincial' in df else []
    territories = df['Territorial']['Territory'].unique().tolist() if 'Territorial' in df else []

    return {"provinces": provinces, "territories": territories}
