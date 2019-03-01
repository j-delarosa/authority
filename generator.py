from random import randint, choice
from string import ascii_letters, digits
import err
import kms


def generate():
        one = ''.join((choice(ascii_letters+digits)) for x in range(50))
        return one

class JSONResponse(object):

    def __init__(self,*args,**kw):
        self.kw = kw
        self.args = args
        header = kw.get('headers')
        self.name = header.get('Name','NOTFOUND')
        self.token = header.get('Auth-Token','NOTFOUND')

    def base_build(self,allow_deny):
        data = {
            "principalId": self.name+ '-' + ''.join((choice(ascii_letters+digits)) for x in range(5)), # The principal user identification associated with the token sent by the client.
            "policyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                    "Action": "execute-api:Invoke",
                    "Effect": allow_deny,
                    "Resource": self.kw['methodArn']
                    }
                ]
            },
            "context": {
                "ApiKey": self.kw['requestContext']['identity']['apiKey'],
                "Name": self.name,
                "Auth-Token": self.token
            },
        }
        if not self.kw['requestContext']['identity'].get('apiKey') == 'null':
            data["usageIdentifierKey"] = self.kw['requestContext']['identity']['apiKey']
        return data

    def build_success(self):
        return self.base_build('Allow')

    def build_failure(self):
        return self.base_build('Deny')