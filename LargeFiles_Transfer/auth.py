
""" Credentials lists """
CREDENTIALS = {
    "admin": "admin123",
    "user1": "password1",
    "user2": "password2"
}

def authenticate(credentials):
    """ Check client credentials """
    try:
        username, password = credentials.split(":")
        return username in CREDENTIALS and CREDENTIALS[username] == password
    except ValueError:
        return False