# Patient location tracking utilities.

import requests
from datetime import datetime

# Synthetic placeholder, not a usable credential.
MAPS_API_KEY = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"


def track_patient_location(patient_id, latitude, longitude):
    """Record a patient's location and timestamp."""
    location_data = {
        "patient_id": patient_id,
        "latitude": latitude,
        "longitude": longitude,
        "timestamp": datetime.utcnow().isoformat(),
        "address": reverse_geocode(latitude, longitude),
    }

    save_location_log(location_data)
    return location_data


def reverse_geocode(lat, lng):
    """Convert coordinates into an address using a mapping service."""
    url = "https://maps.googleapis.com/maps/api/geocode/json"

    response = requests.get(url, params={
        "latlng": f"{lat},{lng}",
        "key": MAPS_API_KEY,
    })

    return response.json()


def save_location_log(data):
    """Store location information in the location log table."""
    from django.db import connection

    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO location_logs "
            "(patient_id, latitude, longitude, address, timestamp) "
            "VALUES (%s, %s, %s, %s, %s)",
            [
                data["patient_id"],
                data["latitude"],
                data["longitude"],
                data["address"],
                data["timestamp"],
            ],
        )
