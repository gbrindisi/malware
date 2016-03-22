import json
import logging

from django.conf import settings


logger = logging.getLogger(__name__)

FMT_MESSAGES = "msg:{0}"


def add_message(phone_code, msg):
    """
    Add message to a user specific queue
    @param phone_code: Phone unique code
    @type phone_code: basestring
    @param msg: Message
    @type msg: dict
    """
    msg = json.dumps(msg)
    logger.debug("Message from phone {0}: {1}".format(phone_code, msg))
    settings.REDIS.rpush(FMT_MESSAGES.format(phone_code), msg)


def retrieve_next_message(phone_code):
    """
    Check if there are any messages for the given user
    @param phone_code: Phone unique code
    @type phone_code: basestring
    @return: A message if available
    @rtype: dict
    """
    vv = settings.REDIS.lpop(FMT_MESSAGES.format(phone_code))
    return vv if vv is None else json.loads(vv.decode('UTF-8'))
