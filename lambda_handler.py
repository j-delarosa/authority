'''Created on Tue Jan  24 04:55:01 2019
@author: jdelarosa'''
from random import randint, choice
from string import ascii_letters, digits
import boto3
import generator
import dynamo as d
import kms
import json
import os
import binascii
import err


class Registrations(object):
    '''
    class that handles registering the api id with the service.
    '''

    def __init__(self, cls, params, **kw):
        '''
        Parameters
        ----------
        cls : str
            expected class name in this case the cls is the above name class Registrations
        params : dict
            keys expected are Name, CreatedBy, ApiId in order to register the api 
        '''
        self.kw = kw
        self.function = getattr(self,kw['cls'])

    def handle(self):

        return self.function()

    def register(self):
        self.kw['params']['Auth-Token'] = generator.generate()
        dyno = d.DynoAuthorize(**self.kw['params'])
        dyno.create_dynamo_record()
        return {"include_in_headers" : {'token':kms.KMS().encrypt(json.dumps({"Auth-Token":self.kw["params"]["Auth-Token"],"Name":self.kw["params"]["Name"]}))}}

    def unregister(self):
        dyno = d.DynoAuthorize(**self.kw['params'])
        return dyno.delete_record()

class Validate(object):
    def __init__(self, **kw):
        self.kw = kw

    def handle(self):
        '''this function will validate the call for a registered api

        The function will utilize the kw coming from the api in order to check the header contents and various Id's

        Parameters
        ----------
        **kw : dict, required
            this is the entire call from api and contains information about the
            headers, the api, and the api context.

        Raises
        ------
        binascii.Error
            this error occurs whenever the encoded string has been modified
        KeyError
            if one of the key arguments was not correctly sent, this error will be caught

        '''
        dyno = d.DynoAuthorize(**self.kw)
        try:
            json_response = generator.JSONResponse(**self.kw)
            # get the record from dynamo using name
            dynorecord = dyno.get_record()
            # add the dynamo record to the headers
            self.kw['headers'] = dynorecord
        except binascii.Error:
            # raise the error if token is wrong
            print('Token is incomplete, please check and retry')
            return json_response.build_failure()
        # if the token structure works then check the contents
        try:
            json_response = generator.JSONResponse(**self.kw)
            if dyno.check_token(dynorecord) and dyno.check_api(self.kw['headers']):
                print('success')
                return json_response.build_success() 
            else:
                print('Auth failed!: Checks failed')
                return json_response.build_failure()
        except KeyError:
            print('Auth failed! Key Failure')
            return json_response.build_failure()

def lambda_handler(event, context=None):
    # print(event)
    '''the lambda handler will be the entry point for calls.

    there is a possibility of 2 calls that can occur. The first call is from api gateway which has a template that wraps the client request. The api
    template is:

    {"cls":"Register","params":$input.json('$')}

    in which the client request to the api is:

    {"Name":"Rubix","CreatedBy":"Jonathan de la Rosa","ApiId":"xdiso517fl"}

    The function will take a look at the first key in the call. If the calls first key is cls, then the code will attempt to register. Required for registration is "Name, ApiId, CreatedBy" where Name is the name of the app or user, ApiId is the api in which the authorizer will be attached to, and created by so we have record of who created the request.

    Parameters
    ----------
    event : dict, required
        call passed from api

    context : obj, required
        information about the lambda container

    '''


    things_to_do = {
        "cls": Registrations,
        "type": Validate}
    return things_to_do[next(iter(event))](**event).handle()

if __name__ == '__main__':
    ''''''