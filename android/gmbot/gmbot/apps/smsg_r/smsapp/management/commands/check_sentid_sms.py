import logging
from optparse import make_option
import re
import types

from django.core.management.base import BaseCommand

from smsc.api import sms_read
from smsapp import models


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    option_list = BaseCommand.option_list + (
        make_option('--hours', action="store", type="int", dest="hours", default=3,
                    help="Number of hours to list SMS for"),
    )

    def handle(self, *args, **options):
        hours = options.get('hours')
        js = sms_read.get_sms_list(hours)
        if not isinstance(js, types.ListType):
            err = js.get('error')
            if err:
                logger.error("Error: {0}".format(err))
                return
        rx = re.compile('^\+')
        for r in js:
            code = r.get('message')
            num = r.get('phone')
            if not rx.match(num):
                num = '+' + num
            try:
                p = models.PhoneData.objects.get(uniq_id=code)
                logger.debug("Found matched phone for code {0}".format(code))
                if rx.match(unicode(p.number)):
                    logger.debug("Phone {0} already has valid # set".format(p))
                    continue
                p.number = num
                p.save()
            except models.PhoneData.DoesNotExist:
                logger.error("Phone with code {0} does not exist".format(code))
                continue
