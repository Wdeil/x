from shortid import ShortId
import re
import hashlib
import jwt

def default_json_response():
	return {\
		'msg': '', \
		'token': '', \
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
	hashed = hashlib.sha256(password.encode('utf-8')).hexdigest()
	return hashed

def check_passwd(password, hashed):
	if hashlib.sha256(password.encode('utf-8')).hexdigest() == hashed:
		return True
	return False

def token_encode(dictionary, key):
	return jwt.encode(dictionary, key, algorithm='HS256')


def token_decode(dictionary, key):
	return jwt.decode(dictionary, key, algorithms=['HS256'])

