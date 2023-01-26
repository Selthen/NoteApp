import string
from re import search
from threading import Event

from Crypto.Random import random
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from password_strength import PasswordStats


min_char = 32
max_char = 127
modulo_char = max_char - min_char
prime_number = 17
char_step = 3

database_ref = "./sqlite3.db"
sha256_rounds = 643346
pbkdf2_rounds = 1111111
allowed_tags = ['p', 'br', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'strong', 'em', 'a', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt']}

def get_random_string(length):
    chars = string.ascii_letters + string.digits + './'
    return ''.join(random.choice(chars) for i in range(length))


def shift_text(text, shift):
    result = ''

    for char in text:
        result += chr(min_char + (ord(char) - min_char + shift) % modulo_char)
        shift += 3

    return result


def adjust_with_shifted(text, desired_size=32):
    result = ''
    i = 0

    while len(result) < desired_size:
        result += shift_text(text, i)
        i += prime_number + char_step * len(text)

    return result[:desired_size]


def encrypt(value, key):
    value = value.encode()
    key_extended = adjust_with_shifted(key).encode()
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key_extended, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(value, AES.block_size))
    return iv + ciphertext


def decrypt(encrypted_value, key):
    iv = encrypted_value[:AES.block_size]
    key_extended = adjust_with_shifted(key).encode()
    cipher = AES.new(key_extended, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_value[AES.block_size:])
    try:
        decrypted = unpad(decrypted, AES.block_size).decode()
    except:
        pass
    return decrypted


# https://pypi.org/project/password-strength/
def verify_password_strength(password):

    stats = PasswordStats(password)
    is_valid = True
    is_valid &= stats.length >= 8
    is_valid &= stats.letters_lowercase >= 1
    is_valid &= stats.letters_uppercase >= 1
    is_valid &= stats.special_characters >= 1
    is_valid &= stats.numbers >= 1

    if not is_valid:
        return "Password must be at least 8 characters long and have at least one digit, special character, lowercase and uppercase letter"

    if stats.strength() < 0.66:
        print(stats.strength())
        return "Too weak password - use more distinct characters or make password slightly longer"

    return None


def delay(time=2):
    Event().wait(timeout=time)


def username_regex(username):
    return bool(search(r'^\w+$', username)) and len(username) <= 32


def password_regex(password):
    return bool(search(r'^[\w `~!@#$%^&*()\\_+\-={}\[\]\'";|:?/>.<,]+$', password)) and len(password) <= 128
