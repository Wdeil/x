from shortid import ShortId
import re
import bcrypt

def default_json_response():
	return {\
		'status': '', \
		'id': '', \
		'username': '', \
		'msg': '', \
	}

def check_uname_passwd(username, password):
    if username and password and isinstance(username, str) and isinstance(password, str):
        return True
    return False

def check_email(email):
	if email and isinstance(email, str) and re.match(r'^[a-z0-9A-Z]([a-z0-9]*[-_]?[a-z0-9]+)*\@([a-z0-9]*[-_]?[a-z0-9]+)+\.[a-z]{2,3}(\.[a-z]{2})?$', email):
		return True
	return False

def shortid_generate():
	return ShortId().generate()


def passwd_hash(password):
	hashed = bcrypt.hashpw(password, bcrypt.gensalt())
	return hashed

def check_passwd(password, hashed):
	if bcrypt.hashpw(password, hashed) == hashed:
		return True
	return False