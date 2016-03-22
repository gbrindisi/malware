import logging

from django.core.management import BaseCommand

from smsapp import models


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    def handle(self, *args, **options):
        for p in models.PhoneData.objects.get_inactive_phones():
            p.inactive = True
            p.save()
            logger.debug("Phone {0} marked as inactive".format(p))
