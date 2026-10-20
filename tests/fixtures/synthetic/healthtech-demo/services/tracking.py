# Location tracking service
# PLANTED VIOLATIONS: V8 (continuous location tracking, not in policy)

import requests
from datetime import datetime

MAPS_API_KEY = "AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"

def track_patient_location(patient_id, latitude, longitude):
    """
    PLANTED V8 — Continuously tracks patient GPS location.
    Location tracking is NOT mentioned in the privacy policy.
    """
    location_data = {
        "patient_id": patient_id,
        "latitude":   latitude,
        "longitude":  longitude,
        "timestamp":  datetime.utcnow().isoformat(),
        "address":    reverse_geocode(latitude, longitude)
    }
    # Store in database
    save_location_log(location_data)
    return location_data


def reverse_geocode(lat, lng):
    """Convert coordinates to address using Google Maps"""
    url = f"https://maps.googleapis.com/maps/api/geocode/json"
    response = requests.get(url, params={
        "latlng": f"{lat},{lng}",
        "key": MAPS_API_KEY
    })
    return response.json()


def save_location_log(data):
    """Save GPS coordinates to location_logs table"""
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute(
            "INSERT INTO location_logs (patient_id, latitude, longitude, address, timestamp) "
            "VALUES (%s, %s, %s, %s, %s)",
            [data['patient_id'], data['latitude'],
             data['longitude'], data['address'], data['timestamp']]
        )
