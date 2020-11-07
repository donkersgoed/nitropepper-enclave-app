"""KMS interaction module."""

import base64
import datetime
import json
import hashlib
import hmac

import requests
import Crypto

from asn1crypto import cms
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import unpad

import libnsm

class NitroKms():
    """KMS interaction class."""

    _region_name = None
    _aws_access_key_id = None
    _aws_secret_access_key = None
    _aws_session_token = None

    def __init__(self):
        """Construct a new NitroKms instance."""
        # Initialize the Rust NSM Library
        self._nsm_fd = libnsm.nsm_lib_init() # pylint:disable=c-extension-no-member
        # Create a new random function `nsm_rand_func`, which
        # utilizes the NSM module.
        self.nsm_rand_func = lambda num_bytes : libnsm.nsm_get_random( # pylint:disable=c-extension-no-member
            self._nsm_fd, num_bytes
        )

        # Force pycryptodome to use the new rand function.
        # Without this, pycryptodome defaults to /dev/random
        # and /dev/urandom, which are not available in Enclaves.
        self._monkey_patch_crypto(self.nsm_rand_func)

        # Generate a new RSA certificate, which will be used to
        # generate the Attestation document and to decrypt results
        # for KMS Decrypt calls with this document.
        self._rsa_key = RSA.generate(2048)
        self._public_key = self._rsa_key.publickey().export_key('DER')

    def set_region(self, region):
        """Set the region for this NitroKms instance."""
        self._region_name = region

    def set_credentials(self, credentials):
        """Set the IAM credentials for this NitroKms instance."""
        self._aws_access_key_id = credentials['aws_access_key_id']
        self._aws_secret_access_key = credentials['aws_secret_access_key']
        self._aws_session_token = None
        if 'aws_session_token' in credentials:
            self._aws_session_token = credentials['aws_session_token']

    def kms_generate_random(self, number_of_bytes):
        """Call the KMS GenerateRandom API."""
        if not isinstance(number_of_bytes, int):
            raise ValueError('number_of_bytes must be an integer')
        if number_of_bytes < 1 or number_of_bytes > 1024:
            raise ValueError('number_of_bytes must be between 1 and 1024 (inclusive)')

        amz_target = 'TrentService.GenerateRandom'
        request_parameters = json.dumps({
            "NumberOfBytes": number_of_bytes
        })
        return self._kms_call(amz_target, request_parameters)

    def kms_encrypt(self, plaintext_bytes, kms_key_id):
        """Call the KMS Encrypt API."""
        amz_target = 'TrentService.Encrypt'
        request_parameters = json.dumps({
            "Plaintext": base64.b64encode(plaintext_bytes).decode('utf-8'),
            "KeyId": kms_key_id,
        })
        return self._kms_call(amz_target, request_parameters)

    def kms_decrypt(self, ciphertext_blob):
        """Call the KMS Decrypt API."""
        amz_target = 'TrentService.Decrypt'
        request_parameters = json.dumps({
            'CiphertextBlob': ciphertext_blob,
            'Recipient': {
                'KeyEncryptionAlgorithm': 'RSAES_OAEP_SHA_1',
                'AttestationDocument': self._get_attestation_doc_b64()
            }
        })
        kms_response = self._kms_call(amz_target, request_parameters)
        ciphertext_for_recipient_b64 = kms_response['CiphertextForRecipient']
        ciphertext_for_recipient = base64.b64decode(ciphertext_for_recipient_b64)

        enveloped_data = self._cms_parse_enveloped_data(ciphertext_for_recipient)
        (encrypted_symm_key, init_vector, block_size, ciphertext_out) = enveloped_data
        decrypted_symm_key = self._rsa_decrypt(self._rsa_key, encrypted_symm_key)
        plaintext_bytes = self._aws_cms_cipher_decrypt(
            ciphertext_out, decrypted_symm_key, block_size, init_vector
        )
        return plaintext_bytes

    def _get_attestation_doc_b64(self):
        """Get the attestation document from /dev/nsm."""
        libnsm_att_doc_cose_signed = libnsm.nsm_get_attestation_doc( # pylint:disable=c-extension-no-member
            self._nsm_fd,
            self._public_key,
            len(self._public_key)
        )
        return base64.b64encode(libnsm_att_doc_cose_signed).decode('utf-8')

    def _kms_call(self, amz_target, request_parameters):
        """Call AWS KMS and return the response."""
        method = 'POST'
        service = 'kms'
        host = f'kms.{self._region_name}.amazonaws.com'
        endpoint = f'https://kms.{self._region_name}.amazonaws.com/'
        content_type = 'application/x-amz-json-1.1'

        now_time = datetime.datetime.utcnow()
        amz_date = now_time.strftime('%Y%m%dT%H%M%SZ')
        date_stamp = now_time.strftime('%Y%m%d')
        canonical_uri = '/'
        canonical_querystring = ''
        canonical_headers = (
            f'content-type:{content_type}\n'
            f'host:{host}\n'
            f'x-amz-date:{amz_date}\n'
            f'x-amz-target:{amz_target}\n'
        )
        signed_headers = 'content-type;host;x-amz-date;x-amz-target'
        payload_hash = hashlib.sha256(request_parameters.encode('utf-8')).hexdigest()
        canonical_request = (
            f'{method}\n'
            f'{canonical_uri}\n'
            f'{canonical_querystring}\n'
            f'{canonical_headers}\n'
            f'{signed_headers}\n'
            f'{payload_hash}'
        )
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = (
            date_stamp + '/' + self._region_name + '/' + service + '/' + 'aws4_request'
        )
        string_to_sign = (
            f'{algorithm}\n'
            f'{amz_date}\n'
            f'{credential_scope}\n' + \
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
        )
        signing_key = self._get_signature_key(
            self._aws_secret_access_key, date_stamp, self._region_name, service
        )
        signature = hmac.new(
            signing_key,
            (string_to_sign).encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        authorization_header = (
            algorithm + ' ' + \
            f'Credential={self._aws_access_key_id}/{credential_scope}, '
            f'SignedHeaders={signed_headers}, '
            f'Signature={signature}'
        )
        headers = {'Content-Type':content_type,
                'X-Amz-Date':amz_date,
                'X-Amz-Target':amz_target,
                'Authorization':authorization_header}
        if self._aws_session_token is not None:
            headers['X-Amz-Security-Token'] = self._aws_session_token

        response = requests.post(endpoint, data=request_parameters, headers=headers)
        if response.status_code != 200:
            error_type = None
            error_message = None
            try:
                error_type = response.json()['__type']
            except: # pylint:disable=bare-except
                pass

            try:
                error_message = response.json()['message']
            except: # pylint:disable=bare-except
                pass

            error_str = f'KMS call failed with status code {response.status_code}.'
            if error_type:
                error_str += f' Error type: {error_type}'
            if error_message:
                error_str += f' Error message: {error_message}'
            raise RuntimeError(error_str)
        return response.json()

    def _get_signature_key(self, key, date_stamp, region_name, service_name):
        """Generate a AWS API signature."""
        k_date = self._sign(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = self._sign(k_date, region_name)
        k_service = self._sign(k_region, service_name)
        k_signing = self._sign(k_service, 'aws4_request')
        return k_signing

    @classmethod
    def _cms_parse_enveloped_data(cls, ciphertext_for_recipient):
        """Return symmetric key, IV, Block Size and ciphertext for serialized CMS content."""
        content_info = cms.ContentInfo.load(ciphertext_for_recipient)
        if content_info.tag != 16:
            raise ValueError('CMS tag is not (16: Sequence)')

        if content_info['content_type'].native != 'enveloped_data':
            raise ValueError('CMS content_type is not enveloped_data')

        enveloped_data = content_info['content']
        recipient = enveloped_data['recipient_infos'][0].chosen
        encrypted_content_info = enveloped_data['encrypted_content_info']
        cipherkey = recipient['encrypted_key'].native

        block_size = encrypted_content_info['content_encryption_algorithm'].encryption_block_size
        init_vector = encrypted_content_info['content_encryption_algorithm'].encryption_iv
        ciphertext = encrypted_content_info['encrypted_content'].native

        return cipherkey, init_vector, block_size, ciphertext

    @classmethod
    def _rsa_decrypt(cls, private_key, encrypted_symm_key):
        """Decrypt the encrypted symmetric key with the RSA private key."""
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_symm_key)

    @classmethod
    def _aws_cms_cipher_decrypt(cls, ciphertext, key, block_size, init_vector):
        """Decrypt the plain text data with the dycrypted key from CMS."""
        cipher = AES.new(key, AES.MODE_CBC, iv=init_vector)
        return unpad(cipher.decrypt(ciphertext), block_size)


    @classmethod
    def _sign(cls, key, msg):
        """Sign a message for the AWS API signature."""
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    @classmethod
    def _monkey_patch_crypto(cls, nsm_rand_func):
        """Monkeypatch Crypto to use the NSM rand function."""
        Crypto.Random.get_random_bytes = nsm_rand_func
        def new_random_read(self, n_bytes): # pylint:disable=unused-argument
            return nsm_rand_func(n_bytes)
        Crypto.Random._UrandomRNG.read = new_random_read # pylint:disable=protected-access
