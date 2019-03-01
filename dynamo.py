import boto3
import time
import err
import kms
import json
import binascii
from botocore.exceptions import ClientError


class DynoAuthorize(object):


    def __init__(self,*args,**kwargs):
        self.dynamo = boto3.resource('dynamodb')
        try:
            client = boto3.client('dynamodb')
            response = client.describe_table(TableName='Authorizer')
        except client.exceptions.ResourceNotFoundException as err:
            if err.response['Error']['Code'] == 'ResourceNotFoundException':
                self.__create_table()
                time.sleep(15)
        self.table = self.dynamo.Table('Authorizer')
        self.kw = kwargs
        self.args = args

    def __create_table(self):
        self.dynamo.create_table(
            TableName='Authorizer',
            BillingMode = 'PAY_PER_REQUEST',
            KeySchema=[
                {
                    'AttributeName': 'Name',
                    'KeyType': 'HASH'  #Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'Name',
                    'AttributeType': 'S'
                }

            ],
            SSESpecification={
                'Enabled': True,
                'SSEType': 'KMS'
            }
        )

    def _prohibit_overwrite(self):
        response = self.table.get_item(
            Key={
                # 'Name':"Rubix"
                'Name':self.kw['Name']
            }
        )
        if response.get("Item"):
            raise err.NameTaken("please use another name, this one has been taken. If this is yours and you need a new key please reach out to eric.barrow@pnmac.com or jonathan.delarosa@pnmac.com")


    def check_api(self, record):
        # print(self.kw)
        if (self.kw['requestContext']['apiId'] == record.get('ApiId')):

            return True
        else:
            return False

    def check_token(self,data):
        if data['Auth-Token'] == self.client_token['Auth-Token']:
            return True
        else:
            return False

    def create_dynamo_record(self):
        if not (
            'Name' in self.kw and
            'CreatedBy' in self.kw and
            'ApiId' in self.kw):
            raise err.IncorrectRegistration("Missing parameters required for registration")
        try:
            self._prohibit_overwrite()
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print('Name Available')
        except err.NameTaken:
            raise

        return self.table.put_item(Item = self.kw)

    def get_record(self):
        try:
            self.client_token = json.loads(kms.KMS(**self.kw).decrypt())
        except:
            raise binascii.Error
        response = self.table.get_item(
            Key={
                'Name':self.client_token['Name']
            }
        )
        try:
            return response["Item"]
        except KeyError as err:
            print('Unauthorized entry, no record found')
            raise

    def delete_record(self):
        try:
            return self.table.delete_item(
                Key = {
                    'Name':self.kw['Name']
                },
                ReturnValues = 'ALL_OLD')['Attributes']
        except KeyError:
            raise err.NameNotFound('Name was not found to delete')
        else:
            raise

