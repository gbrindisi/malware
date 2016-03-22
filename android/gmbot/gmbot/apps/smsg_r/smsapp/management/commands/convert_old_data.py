"""
Converts data in old document format
"""

import logging

from django.core.management import BaseCommand
from django.conf import settings

from smsapp import json_attach

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    def handle(self, *args, **options):
        # convert forms
        for d in settings.MONGO['extra_data'].find({'command': 'forms'}):
            d['data']['type'] = 'forms'
            json_attach.attach_ex(d['code'], d['data'])

