from aiohttp.web import json_response
from json.decoder import JSONDecodeError
from rest_api import elastic
from rest_api.errors import *

from protobuf import user_pb2
from google.protobuf.json_format import MessageToJson

from Crypto.Cipher import AES
from protobuf.payload_pb2 import SimpleSupplyPayload

from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from itsdangerous import BadSignature

import time
import json
import datetime
import bcrypt
import requests
import base64
import logging
import uuid

LOGGER = logging.getLogger(__name__)

role_index_match = {
    "ORG": "0",
    "DIRECTOR": "1",
    "00": "nothing"
}

role_arrays = {
    "ORG",
    "DIRECTOR",
    ""
}


class RouterHandler(object):
    def __init__(self, loop, messenger):
        self._loop = loop
        self._messenger = messenger

    async def create_user(self, request):
        body = await decode_request(request)
        required_fields = ['username', 'password', 'role']
        validate_fields(required_fields, body)

        public_key, private_key = self._messenger.get_new_key_pair()

        username = body.get('username')
        password = body.get('password')
        user_id = str(uuid.uuid4())
        role = body.get('role')
        user = await elastic.get_user_by_username(username)
        if user:
            transaction_id = user['transaction_unique_id']
            data = await _get_transaction(transaction_id)
            if data:
                return json_response({
                    "status": "Failure",
                    "detail": "User already existed"
                })

        if role not in role_arrays:
            return json_response({
                "status": "Failure",
                "detail": "Role not in Role list"
            })

        transaction_unique = await self._messenger.send_create_user_transaction(
            private_key=private_key,
            username=username,
            role=role,
            timestamp=get_time()
        )
        transaction_unique_id = transaction_unique.transactions[0].header_signature
        encrypted_private_key = encrypt_private_key(
            request.app['aes_key'], public_key, private_key)
        hashed_password = bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())

        await elastic.create_user(
            username=username,
            role=role,
            hashed_password=hashed_password,
            public_key=public_key,
            encrypted_private_key=encrypted_private_key,
            transaction_unique_id=transaction_unique_id
        )
        return json_response({
            "status": "Success",
            "detail": "User created",
            "user_id": user_id
        })

    async def login(self, request):
        body = await decode_request(request)
        required_fields = ['username', 'password']
        validate_fields(required_fields, body)

        username = body.get('username')
        password = bytes(body.get('password'), 'utf-8')
        user = await elastic.get_user_by_username(username)
        if user is None:
            return json_response({
                "status": "Failure",
                "detail": "User does not exist"
            })

        transaction_id = user['transaction_unique_id']
        data = await _get_transaction(transaction_id)
        if data is None:
            return json_response({
                "status": "Failure",
                "detail": "User does not exist"
            })

        hashed_password = user.get('hashed_password')  # Nen truy van sawtooth
        if not bcrypt.checkpw(password, bytes.fromhex(hashed_password)):
            return json_response({
                "status": "Failure",
                "detail": "Wrong password"
            })

        token = generate_auth_token(request.app['secret_key'], user['username'])

        return json_response({"status": "Success", "authorization": token})

    async def create_com(self, request):
        auth = await self._authorize(request)
        role = int(role_index_match[auth['role']])
        if role not in [user_pb2.User.ORG]:
            return json_response({
                'status': 'Failure',
                'details': 'Permission denied'
            })
        private_key = auth['private_key']
        body = await decode_request(request)

        required_fields = ['name']
        validate_fields(required_fields, body)

        com_id = str(uuid.uuid4())
        name = body.get('name')
        timestamp = get_time()

        check_id = await elastic.get_company_by_id(com_id)
        if check_id:
            return json_response({
                'status': 'Failure',
                'details': 'Company id has been used'})

        transaction_unique = await self._messenger.send_create_com_transaction(
            private_key=private_key,
            com_id=com_id,
            name=name,
            timestamp=timestamp
        )
        transaction_unique_id = transaction_unique.transactions[0].header_signature

        await elastic.create_com(
            transaction_id=transaction_unique_id,
            com_id=com_id,
            name=name,
            timestamp=timestamp
        )

        return json_response({
            "status": "Success",
            "com_id": com_id,
            "transaction_id": transaction_unique_id
        })

    async def update_com(self, request):
        auth = await self._authorize(request)
        role = int(role_index_match[auth['role']])
        if role not in [user_pb2.User.ORG]:
            return json_response({
                "status": "Failure",
                "details": "Permission denied"
            })
        private_key = auth['private_key']
        body = await decode_request(request)

        required_fields = ['id', 'establish', 'address']
        validate_fields(required_fields, body)

        com_id = body.get('id')
        com = await elastic.get_company_by_id(com_id)
        if com is None:
            return json_response({
                "status": "Failure",
                "details": "Company does not exists"
            })

        transaction_id = com['transaction_id']
        data = await _get_transaction(transaction_id)
        if data is None:
            return json_response({
                "status": "Failure",
                "details": "Company does not exists"
            })

        timestamp = get_time()
        transaction_unique = await self._messenger.send_update_com_transaction(
            private_key=private_key,
            com_id=com_id,
            establish=body.get('establish'),
            address=body.get('address'),
            timestamp=timestamp
        )
        transaction_unique_id = transaction_unique.transactions[0].header_signature

        await elastic.update_com(
            transaction_id=transaction_unique_id,
            com_id=com_id,
            establish=body.get('establish'),
            address=body.get('address'),
            timestamp=timestamp
        )
        return json_response({
            "status": "Success",
            "transaction_id": transaction_unique_id
        })

    async def create_emp(self, request):
        auth = await self._authorize(request)
        role = int(role_index_match[auth['role']])
        if role not in [user_pb2.User.DIRECTOR]:
            return json_response({
                'status': 'Failure',
                'details': 'Permission denied'
            })
        private_key = auth['private_key']
        body = await decode_request(request)

        required_fields = ['name']
        validate_fields(required_fields, body)

        emp_id = str(uuid.uuid4())
        name = body.get('name')
        timestamp = get_time()

        check_id = await elastic.get_employee_by_id(emp_id)
        if check_id:
            return json_response({
                'status': 'Failure',
                'details': 'Company id has been used'})

        transaction_unique = await self._messenger.send_create_emp_transaction(
            private_key=private_key,
            emp_id=emp_id,
            name=name,
            timestamp=timestamp
        )
        transaction_unique_id = transaction_unique.transactions[0].header_signature

        await elastic.create_emp(
            transaction_id=transaction_unique_id,
            emp_id=emp_id,
            name=name,
            timestamp=timestamp
        )

        return json_response({
            "status": "Success",
            "emp_id": emp_id,
            "transaction_id": transaction_unique_id
        })

    async def update_emp(self, request):
        auth = await self._authorize(request)
        role = int(role_index_match[auth['role']])
        if role not in [user_pb2.User.DIRECTOR]:
            return json_response({
                "status": "Failure",
                "details": "Permission denied"
            })
        private_key = auth['private_key']
        body = await decode_request(request)

        required_fields = ['id', 'age', 'address', 'email', 'com_id']
        validate_fields(required_fields, body)

        emp_id = body.get('id')
        emp = await elastic.get_employee_by_id(emp_id)
        if emp is None:
            return json_response({
                "status": "Failure",
                "details": "Employee does not exists"
            })

        transaction_id = emp['transaction_id']
        data = await _get_transaction(transaction_id)
        if data is None:
            return json_response({
                "status": "Failure",
                "details": "Employee does not exists"
            })

        com_id = body.get('com_id')
        com = await elastic.get_company_by_id(com_id)
        if com is None:
            return json_response({
                "status": "Failure",
                "details": "Company does not exists"
            })

        transaction_id = com['transaction_id']
        data = await _get_transaction(transaction_id)
        if data is None:
            return json_response({
                "status": "Failure",
                "details": "Company does not exists"
            })

        timestamp = get_time()
        transaction_unique = await self._messenger.send_update_emp_transaction(
            private_key=private_key,
            emp_id=emp_id,
            age=body.get('age'),
            address=body.get('address'),
            email=body.get('email'),
            com_id=com_id,
            timestamp=timestamp
        )
        transaction_unique_id = transaction_unique.transactions[0].header_signature

        await elastic.update_emp(
            transaction_id=transaction_unique_id,
            emp_id=emp_id,
            age=body.get('age'),
            address=body.get('address'),
            email=body.get('email'),
            com_id=com_id,
            timestamp=timestamp
        )
        return json_response({
            "status": "Success",
            "transaction_id": transaction_unique_id
        })

    async def _authorize(self, request):
        token = request.headers.get('AUTHORIZATION')
        if token is None:
            raise ApiUnauthorized('No auth token provided')
        token_prefixes = ('Bearer', 'Token')
        for prefix in token_prefixes:
            if prefix in token:
                token = token.partition(prefix)[2].strip()
        try:
            token_dict = deserialize_auth_token(
                request.app['secret_key'],
                token
            )
        except BadSignature:
            raise ApiUnauthorized('Invalid auth token')
        username = token_dict.get('username')

        user = await elastic.get_user_by_username(username)
        if len(user) == 0:
            raise ApiUnauthorized('Token is not associated with an user')
        role = user['role']
        return {
            'role': role,
            'private_key': decrypt_private_key(
                request.app['aes_key'],
                user['public_key'],
                user['encrypted_private_key']
            )
        }

    async def get_com(self, request):
        auth = await self._authorize(request)
        role = int(role_index_match[auth['role']])
        if role not in [user_pb2.User.ORG]:
            return json_response({
                'status': 'Failure',
                'details': 'Permission denied'
            })

        try:
            com_id = request.rel_url.query['id']
        except:
            raise ApiBadRequest("'id' parameter is required")

        res = await elastic.get_com(com_id)
        # return json_response(res)
        transactions = []
        for tx in res:
            transaction_id = tx['transaction_id']
            payload = await _get_transaction(transaction_id)
            transactions.append(payload)
        return get_response(transactions)

    async def get_emp(self, request):
        auth = await self._authorize(request)
        role = int(role_index_match[auth['role']])
        if role not in [user_pb2.User.DIRECTOR]:
            return json_response({
                'status': 'Failure',
                'details': 'Permission denied'
            })

        try:
            emp_id = request.rel_url.query['id']
        except:
            raise ApiBadRequest("'id' parameter is required")

        res = await elastic.get_emp(emp_id)

        transactions = []
        for tx in res:
            transaction_id = tx['transaction_id']
            payload = await _get_transaction(transaction_id)
            transactions.append(payload)
        return get_response(transactions)

    async def get_transactions(self, request):
        url = "http://rest-api:8008/transactions"
        response = requests.get(url)

        if response.status_code == 200:
            try:
                content = json.loads(response.content)
                transactions_dict = content['data']
                transactions = []
                for transaction_dict in transactions_dict:
                    transaction_id = transaction_dict['header_signature']
                    payload_string = transaction_dict['payload']
                    data_model = SimpleSupplyPayload()
                    data_model.ParseFromString(base64.b64decode(payload_string))
                    payload = await get_data_transaction(data_model)

                    transactions.append({
                        "transaction_id": transaction_id,
                        "payload": payload
                    })
                return get_response(transactions)
            except Exception as err:
                LOGGER.error(err)
                return json_response({"transactions": ""})

        return json_response({
            "status": "Failure",
            "code": response.status_code
        })


async def _get_transaction(transaction_id):
    url = "http://rest-api:8008/transactions/" + transaction_id
    response = requests.get(url)

    if response.status_code == 200:
        try:
            content = json.loads(response.content)
            payload_string = content['data']['payload']
            data_model = SimpleSupplyPayload()
            data_model.ParseFromString(base64.b64decode(payload_string))
            payload = await get_data_transaction(data_model)
            data = {
                "transaction_id": transaction_id,
                "payload": payload
            }
            return data
        except Exception as err:
            LOGGER.error(err)
            return None

    return None


async def get_data_transaction(data_model):
    json_data = json.loads(MessageToJson(data_model, preserving_proto_field_name=True))
    try:
        if data_model.HasField('create_user') and data_model.action == SimpleSupplyPayload.CREATE_USER:
            return json_data['create_user']
        if data_model.HasField('create_com') and data_model.action == SimpleSupplyPayload.CREATE_COM:
            return json_data['create_com']
        if data_model.HasField('update_com') and data_model.action == SimpleSupplyPayload.UPDATE_COM:
            return json_data['update_com']
        if data_model.HasField('create_emp') and data_model.action == SimpleSupplyPayload.CREATE_EMP:
            return json_data['create_emp']
        if data_model.HasField('update_emp') and data_model.action == SimpleSupplyPayload.UPDATE_EMP:
            return json_data['update_emp']
    except (KeyError, ValueError, TypeError) as e:
        LOGGER.error(e)


def get_response(data, status=200):
    return json_response(
        status=status,
        text=json.dumps(
            data,
            indent=2,
            separators=(',', ':'),
            sort_keys=False
        )
    )


async def decode_request(request):
    try:
        return await request.json()
    except JSONDecodeError:
        raise ApiBadRequest('Improper JSON format')


def validate_fields(required_fields, body):
    for field in required_fields:
        if body.get(field) is None:
            raise ApiBadRequest("'{}' parameter is required".format(field))


def get_time():
    dts = datetime.datetime.utcnow()
    return round(time.mktime(dts.timetuple()) + dts.microsecond/1e6)


def encrypt_private_key(aes_key, public_key, private_key):
    init_vector = bytes.fromhex(public_key[:32])
    cipher = AES.new(bytes.fromhex(aes_key), AES.MODE_CBC, init_vector)
    return cipher.encrypt(private_key)


def decrypt_private_key(aes_key, public_key, encrypted_private_key):
    init_vector = bytes.fromhex(public_key[:32])
    cipher = AES.new(bytes.fromhex(aes_key), AES.MODE_CBC, init_vector)
    private_key = cipher.decrypt(bytes.fromhex(encrypted_private_key))
    return private_key


def generate_auth_token(secret_key, username):
    serializer = Serializer(secret_key)
    token = serializer.dumps({'username': username})
    return token.decode('ascii')


def deserialize_auth_token(secret_key, token):
    serializer = Serializer(secret_key)
    return serializer.loads(token)
