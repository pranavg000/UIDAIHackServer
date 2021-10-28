import string
import random


AUTH_TOKEN_LEN = 16
SHAREABLE_CODE_LEN = 9

def getRandAlNum(len):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(len))

def getRandAl(len):
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(len))

