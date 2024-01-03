import random
from typing import Dict

from utils.aes import random_key, aes_ecb_encrypt, aes_ecb_decrypt
from utils.pkcs import pkcs7_pad, pkcs7_unpad, pkcs7_pad_str


def parse_cookie(cookie: str) -> Dict:
    result = {}
    for item in cookie.split('&'):
        key, value = item.split('=')
        result[key] = value

    return result


def create_cookie(obj: Dict) -> str:
    return '&'.join([f"{key}={value}" for key, value in obj.items()])


def profile_for(email: str) -> str:
    # Could do something nicer
    assert '@' in email
    email = email.replace('=', '_').replace('&', '_')

    return create_cookie({
        'email': email,
        'uid': 10,  # TODO: Have a UID that changes based on the email
        'role': 'user'
    })


KEY_LENGTH = random.choice([16, 32])
SECRET_KEY = random_key(KEY_LENGTH)


def get_encrypted_user_session(email: str) -> bytes:
    padded_text = pkcs7_pad(profile_for(email).encode(), KEY_LENGTH)
    return aes_ecb_encrypt(padded_text, SECRET_KEY)


def get_decrypted_user_session(ciphertext: bytes) -> Dict:
    decrypted_text = aes_ecb_decrypt(ciphertext, SECRET_KEY)
    unpadded_text = pkcs7_unpad(decrypted_text)
    user = parse_cookie(unpadded_text.decode())

    print(f'This user is {user["email"]}, with role {user["role"]} and uid {user["uid"]}')
    return user


def determine_block_size() -> int:
    initial_length = len(get_encrypted_user_session('a@b'))
    i = 2
    while True:
        payload = 'a' * i + '@b'
        length = len(get_encrypted_user_session(payload))
        if length > initial_length:
            return length - initial_length
        i += 1


def pwn_user():
    block_size = determine_block_size()

    # Craft a session that includes only the cipher text of the role in the final block
    email_payload = 'a' * ((block_size * 2) - len('email=') - len('@a.b') - len('&uid=10&role=')) + '@a.b'
    encrypted_user_session = get_encrypted_user_session(email_payload)
    user_block = encrypted_user_session[:-block_size]

    email_payload = 'a' * (block_size - len('email=') - len('@a.b')) + '@a.b'
    payload = email_payload + pkcs7_pad_str('admin', block_size)
    admin_block = get_encrypted_user_session(payload)[block_size:block_size*2]
    encrypted_user_session = user_block + admin_block

    decrypted_user_session = get_decrypted_user_session(encrypted_user_session)
    return decrypted_user_session


def test_pwn_user():
    user = pwn_user()
    assert user['role'] == 'admin'