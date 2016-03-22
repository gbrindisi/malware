import StringIO
import json
import logging
import pycurl

from django.conf import settings


logger = logging.getLogger(__name__)


def get_sms_list(hours):
    c = pycurl.Curl()
    c.setopt(pycurl.PROXY, settings.TOR_PROXY)
    c.setopt(pycurl.PROXYPORT, 9050)
    c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)
    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    url = "https://smsc.ru/sys/get.php?login={0}&psw={1}&get_answers=1&fmt=3&hour={2}".format(settings.SMSC_USER,
                                                                                              settings.SMSC_PASSWORD,
                                                                                              hours)
    c.setopt(pycurl.URL, url)
    b = StringIO.StringIO()
    c.setopt(pycurl.WRITEFUNCTION, b.write)
    c.perform()
    jss = b.getvalue()
    d = json.JSONDecoder()
    try:
        res = d.decode(jss)
    except ValueError:
        logger.warn("Error decoding json: %s" % jss)
        return None
    return res
