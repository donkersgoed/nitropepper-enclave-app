"""Enclave NitroPepper application."""

import base64
import json
import socket
import bcrypt

from bcrypt import _bcrypt
from kms import NitroKms

ENCLAVE_PORT = 5000

def main():
    """Run the nitro enclave application."""
    # Bind and listen on vsock.
    vsock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) # pylint:disable=no-member
    vsock.bind((socket.VMADDR_CID_ANY, ENCLAVE_PORT)) # pylint:disable=no-member
    vsock.listen()

    # Initialize a KMS class
    nitro_kms = NitroKms()
    print('Listening...')

    while True:
        conn, _addr = vsock.accept()
        print('Received new connection')
        payload = conn.recv(4096)

        # Load the JSON data provided over vsock
        try:
            parent_app_data = json.loads(payload.decode())
            kms_credentials = parent_app_data['kms_credentials']
            kms_region = parent_app_data['kms_region']
        except Exception as exc: # pylint:disable=broad-except
            msg = f'Exception ({type(exc)}) while loading JSON data: {str(exc)}'
            content = {
                'success': False,
                'error': msg
            }
            conn.send(str.encode(json.dumps(content)))
            conn.close()
            continue

        nitro_kms.set_region(kms_region)
        nitro_kms.set_credentials(kms_credentials)

        if 'action' in parent_app_data:
            if parent_app_data['action'] == 'generate_hash_and_pepper':
                content = process_generate_hash_and_pepper(nitro_kms, parent_app_data)
            elif parent_app_data['action'] == 'validate_credentials':
                content = process_validate_credentials(nitro_kms, parent_app_data)
            else:
                content = {
                    'success': False,
                    'error': f"Unknown action: {parent_app_data['action']}"
                }

        else:
            content = {
                'success': False,
                'error': 'No action provided'
            }

        conn.send(str.encode(json.dumps(content)))
        conn.close()
        print('Closed connection')


def process_validate_credentials(nitro_kms, parent_app_data):
    """Process a validate_credentials command."""
    # Validate all required keys are present
    mandatory_keys = [
        'kms_key', 'password', 'password_hash', 'encrypted_pepper'
    ]
    for mandatory_key in mandatory_keys:
        if mandatory_key not in parent_app_data:
            return {
                'success': False,
                'error': f'Mandatory key {mandatory_key} is missing'
            }

    # Execute the actual call
    return validate_credentials(
        nitro_kms,
        parent_app_data['password'],
        parent_app_data['password_hash'],
        parent_app_data['encrypted_pepper']
    )

def process_generate_hash_and_pepper(nitro_kms, parent_app_data):
    """Process a generate_hash_and_pepper command."""
    # Validate all required keys are present
    mandatory_keys = ['password', 'kms_key']
    for mandatory_key in mandatory_keys:
        if mandatory_key not in parent_app_data:
            return {
                'success': False,
                'error': f'Mandatory key {mandatory_key} is missing'
            }
    # Execute the actual call
    return generate_hash_and_pepper(
        nitro_kms,
        parent_app_data['kms_key'],
        parent_app_data['password']
    )

def validate_credentials(nitro_kms, password, password_hash_b64, encrypted_pepper_b64):
    """Decrypt the pepper, hash the given password with the pepper, and compare the results."""
    try:
        decrypted_pepper_bytes = nitro_kms.kms_decrypt(
            ciphertext_blob=encrypted_pepper_b64
        )
    except Exception as exc: # pylint:disable=broad-except
        return {
            'success': False,
            'error': f'decrypt failed: {str(exc)}'
        }

    derived_key = bcrypt.hashpw(
        password=password.encode('utf-8'),
        salt=decrypted_pepper_bytes
    )

    ddb_password_hash_b64 = base64.b64encode(derived_key).decode('utf-8')
    return {
        'success': True,
        'credentials_valid': password_hash_b64 == ddb_password_hash_b64
    }

def generate_hash_and_pepper(nitro_kms, kms_key, password):
    """
    Generate a pepper and return a hashed password.

    The full process:
    1) Generate random 32 byte string
    2) Use that as a salt to hash the password
    3) Encrypt the byte string with KMS
    4) Return the hashed password and the encrypted salt (now a pepper)
    """
    def gensalt(rounds: int = 12, prefix: bytes = b"2b") -> bytes:
        if prefix not in (b"2a", b"2b"):
            raise ValueError("Supported prefixes are b'2a' or b'2b'")

        if rounds < 4 or rounds > 31:
            raise ValueError("Invalid rounds")

        salt = nitro_kms.nsm_rand_func(16)
        output = _bcrypt.ffi.new("char[]", 30) # pylint:disable=c-extension-no-member
        _bcrypt.lib.encode_base64(output, salt, len(salt)) # pylint:disable=c-extension-no-member

        return (
            b"$"
            + prefix
            + b"$"
            + ("%2.2u" % rounds).encode("ascii")
            + b"$"
            + _bcrypt.ffi.string(output) # pylint:disable=c-extension-no-member
        )
    try:
        bcrypt.gensalt = gensalt
        bcrypt_salt_bytes = bcrypt.gensalt()
    except Exception as exc: # pylint:disable=broad-except
        return {
            'success': False,
            'error': f'generate_random failed: {str(exc)}'
        }

    # Use bcrypt.hashpw to hash the provided password (converted to bytes) using the
    # random bytes generated above as a salt. The result is also binary.
    derived_key = bcrypt.hashpw(
        password=password.encode('utf-8'),
        salt=bcrypt_salt_bytes
    )

    # Encrypt the random byte string so we can return it to the caller.
    try:
        encrypt_response = nitro_kms.kms_encrypt(
            kms_key_id=kms_key,
            plaintext_bytes=bcrypt_salt_bytes
        )
    except Exception as exc: # pylint:disable=broad-except
        return {
            'success': False,
            'error': f'encrypt failed: {str(exc)}'
        }

    password_hash_b64 = base64.b64encode(derived_key).decode('utf-8')
    encrypted_pepper_b64 = encrypt_response['CiphertextBlob']

    return {
        'success': True,
        'data': {
            'password_hash_b64': password_hash_b64,
            'encrypted_pepper_b64': encrypted_pepper_b64
        }
    }

if __name__ == '__main__':
    main()
