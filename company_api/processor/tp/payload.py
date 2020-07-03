from sawtooth_sdk.processor.exceptions import InvalidTransaction
from protobuf import payload_pb2


class SupplyPayload(object):
    def __init__(self, payload):
        self._transaction = payload_pb2.SimpleSupplyPayload()
        self._transaction.ParseFromString(payload)

    @property
    def action(self):
        return self._transaction.action

    @property
    def data(self):
        if self._transaction.HasField('create_user') and \
            self._transaction.action == \
                payload_pb2.SimpleSupplyPayload.CREATE_USER:
            return self._transaction.create_user
        if self._transaction.HasField('create_com') and \
            self._transaction.action == \
                payload_pb2.SimpleSupplyPayload.CREATE_COM:
            return self._transaction.create_com
        if self._transaction.HasField('update_com') and \
            self._transaction.action == \
                payload_pb2.SimpleSupplyPayload.UPDATE_COM:
            return self._transaction.update_com
        if self._transaction.HasField('create_emp') and \
            self._transaction.action == \
                payload_pb2.SimpleSupplyPayload.CREATE_EMP:
            return self._transaction.create_emp
        if self._transaction.HasField('update_emp') and \
            self._transaction.action == \
                payload_pb2.SimpleSupplyPayload.UPDATE_EMP:
            return self._transaction.update_emp

        raise InvalidTransaction('Action does not match payload data')

    @property
    def timestamp(self):
        return self._transaction.timestamp
