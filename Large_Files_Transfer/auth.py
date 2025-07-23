"""Credentials lists with priority"""
CREDENTIALS = {
    "admin": {"password": "admin123", "priority": 1},  # High priority
    "user1": {"password": "password1", "priority": 0},  # Low priority
    "user2": {"password": "password2", "priority": 0}   # Low priority
}

def authenticate(credentials):
    """Check client credentials and return (success, priority)."""
    try:
        username, password = credentials.split(":")
        if username in CREDENTIALS and CREDENTIALS[username]["password"] == password:
            return True, CREDENTIALS[username]["priority"]
        return False, 0
    except ValueError:
        return False, 0