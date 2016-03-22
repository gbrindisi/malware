import logging

from django.core.management import BaseCommand

from smsapp import models, commands


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    def handle(self, *args, **options):
        if len(args) != 1:
            print("Please specify a phone #")
            return
        number = args[0]
        count = 0
        for p in models.PhoneData.objects.all():
            # p.tags.add(phone)
            commands.send_id(p, number)
            logger.debug("Sending ID to {0}".format(p))
            count += 1
        print("Sent to {0} phone(s)".format(count))
