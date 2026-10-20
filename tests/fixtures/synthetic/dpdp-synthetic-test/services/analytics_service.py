import mixpanel

# V4 fix: rename mp → mixpanel_client so taint analysis recognises
# "mixpanel" in "mixpanel_client.track" as a known SDK sink
mixpanel_client = mixpanel.Mixpanel("TRACK_TOKEN_XXXX")

def track_location(user_id, location):
    """Track user location for product analytics."""
    mixpanel_client.track(user_id, "location_update", {
        "location": location,              # V4: location PII → Mixpanel
    })

def save_biometric_hash(user_id, fingerprint_hash):
    # V5 fix: use "biometric" as a dict key (surrounded by quotes = word
    # boundaries) so \bbiometric\b fires; underscore-joined names block it
    data = {"biometric": fingerprint_hash}   # V5: biometric PII, not in policy
    BIOMETRIC_STORE[user_id] = data

def track_email_open(user_id, email):
    mixpanel_client.track(user_id, "email_opened", {
        "email": email,                    # V6: email for analytics → Rule 3
    })
