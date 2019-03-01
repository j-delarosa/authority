import boto3
import os
import base64


class KMS(object):


    def __init__(self, *args,**kw):
        self.kw = kw
        self.args = args
        self.client = boto3.client('kms')

    def encrypt(self, text):
        return base64.b64encode(self.client.encrypt(
            KeyId=os.environ['kms_id'],
            Plaintext=text,
            EncryptionContext={
                'Authorizer': 'Register'
            }
        )['CiphertextBlob']).decode()


    def decrypt(self):
        return self.client.decrypt(
            CiphertextBlob=base64.b64decode(self.kw['headers']['token'].encode()),
            EncryptionContext={
                'Authorizer': 'Register'
            }
        )['Plaintext'].decode()