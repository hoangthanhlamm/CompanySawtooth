from elasticsearch import Elasticsearch
import logging

LOGGER = logging.getLogger(__name__)
# es = Elasticsearch([{"host": "178.128.217.254", "port": "9200"}])
es = Elasticsearch([{"host": "elasticsearch", "port": "9200"}])


def create_user_index():
    if not es.indices.exists(index="company_manager"):
        body = {
            "mappings": {
                "properties": {
                    "username": {"type": "keyword"},
                    "role": {"type": "text"},
                    "hashed_password": {"type": "text"},
                    "public_key": {"type": "text"},
                    "encrypted_private_key": {"type": "text"},
                    "transaction_unique_id": {"type": "text"}
                }
            }
        }
        try:
            res = es.indices.create(index="company_manager", body=body)
            return res
        except Exception as err:
            LOGGER.error(err)


create_user_index()


def ping():
    body = {
        "query": {
            "match": {
                "username": 'hoang_thanh_lam'
            }
        }
    }
    try:
        res = es.search(index='company_manager', body=body)
        return res['hits']['hits'][0]['_source']
    except:
        return None


ping()


async def get_user_by_username(username):
    body = {
        "query": {
            "match": {
                "username": username
            }
        }
    }
    res = es.search(index='company_manager', body=body)
    try:
        re = res['hits']['hits']
        return re[len(re)-1]['_source']
    except:
        return None


async def create_user(username, role, hashed_password, public_key, encrypted_private_key, transaction_unique_id):
    body = {
        "username": username,
        "role": role,
        "hashed_password": hashed_password.hex(),
        "public_key": public_key,
        "encrypted_private_key": encrypted_private_key.hex(),
        "transaction_unique_id": transaction_unique_id
    }
    res = es.index(index='company_manager', doc_type='_doc', body=body)
    return res


def create_company_index():
    if not es.indices.exists(index="company_index"):
        body = {
            "mappings": {
                "properties": {
                    "transaction_id": {"type": "text"},
                    "com_id": {"type": "keyword"},
                    "name": {"type": "text"},
                    "timestamp": {"type": "date", "format": "epoch_second"}
                }
            }
        }
        try:
            res = es.indices.create(index="company_index", body=body)
            return res
        except Exception as err:
            LOGGER.error(err)


def create_employee_index():
    if not es.indices.exists(index="employee_index"):
        body = {
            "mappings": {
                "properties": {
                    "transaction_id": {"type": "text"},
                    "emp_id": {"type": "keyword"},
                    "name": {"type": "text"},
                    "timestamp": {"type": "date", "format": "epoch_second"}
                }
            }
        }
        try:
            res = es.indices.create(index="employee_index", body=body)
            return res
        except Exception as err:
            LOGGER.error(err)


create_company_index()
create_employee_index()


async def create_com(transaction_id, com_id, name, timestamp):
    body = {
        "transaction_id": transaction_id,
        "com_id": com_id,
        "name": name,
        "timestamp": timestamp
    }
    res = es.index(index="company_index", doc_type="_doc", body=body)
    return res


async def get_company_by_id(com_id):
    body = {
        "query": {
            "match": {
                "com_id": com_id
            }
        }
    }
    res = es.search(index="company_index", body=body)
    try:
        re = res['hits']['hits']
        return re[len(re)-1]['_source']
    except:
        return None


async def update_com(transaction_id, com_id, establish, address, timestamp):
    body = {
        "transaction_id": transaction_id,
        "com_id": com_id,
        "establish": establish,
        "address": address,
        "timestamp": timestamp
    }
    # res = es.search(index="company_index", body=)
    res = es.index(index="company_index", body=body)
    return res


async def get_com(com_id):
    body = {
        "query": {
            "bool": {
                "must": {
                    "match": {
                        "com_id": com_id
                    }
                }
            }
        }
    }
    res = es.search(index="company_index", body=body)
    try:
        _return = []
        txs = res['hits']['hits']
        for tx in txs:
            _return.append(tx['_source'])
        return _return
    except Exception as err:
        LOGGER.error(err)
        return []


async def create_emp(transaction_id, emp_id, name, timestamp):
    body = {
        "transaction_id": transaction_id,
        "emp_id": emp_id,
        "name": name,
        "timestamp": timestamp
    }
    res = es.index(index="employee_index", doc_type="_doc", body=body)
    return res


async def get_employee_by_id(emp_id):
    body = {
        "query": {
            "match": {
                "emp_id": emp_id
            }
        }
    }
    res = es.search(index="employee_index", body=body)
    try:
        re = res['hits']['hits']
        return re[len(re)-1]['_source']
    except:
        return None


async def update_emp(transaction_id, emp_id, age, address, email, com_id, timestamp):
    body = {
        "transaction_id": transaction_id,
        "emp_id": emp_id,
        "age": age,
        "address": address,
        "email": email,
        "com_id": com_id,
        "timestamp": timestamp
    }
    # _res = await get_employee_by_id(emp_id)
    # _id = _res['_id']
    res = es.index(index="employee_index", body=body)
    return res


async def get_emp(emp_id):
    body = {
        "query": {
            "bool": {
                "must": {
                    "match": {
                        "emp_id": emp_id
                    }
                }
            }
        }
    }
    res = es.search(index="employee_index", body=body)
    try:
        _return = []
        txs = res['hits']['hits']
        for tx in txs:
            _return.append(tx['_source'])
        return _return
    except Exception as err:
        LOGGER.error(err)
        return []
