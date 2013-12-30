"""STAMP Auth (SSH Two Factor Authentication Module in Python)
www.chokepoint.net

This module will require the use of a one time PIN sent via SMS. 
Once the PIN has been verified, the user will be prompted to enter
their normal password in order to complete the authentication.

Phone numbers should be stored in the standard comment section 
in /etc/passwd (555-555-5555). Default format has office phone number 
as the third option. Can be set with usermod <user> -c ',,555-555-5555,'"""

import random, string, hashlib, requests
import pwd

class InvalidNumber(Exception):
	"""Raised if an invalid phone number is passed to the class"""
	pass

class TextDrop:
	"""Simple class to send SMS through www.txtdrop.com"""
	def __init__(self, pin, phone_num):
		self.pin = pin
		self.phone_num = phone_num
		
		self.url = "http://www.txtdrop.com"
		self.email = "admin@chokepoint.net" # Change me please
		self.params = {"emailfrom": self.email, "body": "One time PIN: " + str(pin),
		"submitted": 1, "submit": "Send"}
		
	def parse_number(self):
		"""Adds npa, exchange, and number to the HTTP parameters"""
		try:
			self.params['npa'], self.params['exchange'], self.params['number'] = self.phone_num.split('-')
			return 1
		except ValueError:
			raise InvalidNumber(self.phone_num)

	def send_text(self):
		try:
			self.parse_number()
		except:
			raise
			
		resp = requests.post(self.url, data=self.params)
		if "Invalid mobile number" in resp.content:
			raise InvalidNumber(self.phone_num)

def get_hash(plain_text):
	"""return sha512 digest of given plain text"""
	key_hash = hashlib.sha512()
	key_hash.update(plain_text)
	
	return key_hash.digest()

def get_user_number(user):
	"""Extract user's phone number for pw entry"""
	try:
		comments = pwd.getpwnam(user).pw_gecos
	except KeyError: # Bad user name
		return -1
	
	try:
		return comments.split(',')[2] # Return Office Phone
	except IndexError: # Bad comment section format
		return -1
		
def gen_key(user_number, length):
	"""Generate the key and send text to the user's phone"""
	pin = ''.join(random.choice(string.digits) for i in range(length))
	sms = TextDrop(pin, user_number)
	try:
		sms.send_text()
	except:
		raise
		
	return get_hash(pin)
	
def pam_sm_authenticate(pamh, flags, argv):
	PIN_LENGTH = 8 # Length of one time PIN
	try:
		user = pamh.get_user()
		user_number = get_user_number(user)
	except pamh.exception, e:
		return e.pam_result
	if user is None or user_number == -1:
		return pamh.PAM_USER_UNKNOWN
		
	pin = gen_key(user_number, PIN_LENGTH)
	
	for attempt in range(0,3): # 3 attempts to enter the one time PIN
		msg = pamh.Message(pamh.PAM_PROMPT_ECHO_OFF, "Enter one time PIN: ")
		resp = pamh.conversation(msg)

		if get_hash(resp.resp) == pin:
			return pamh.PAM_SUCCESS
		else:
			continue
	return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
	return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
	return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
	return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
	return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
	return pamh.PAM_SUCCESS
