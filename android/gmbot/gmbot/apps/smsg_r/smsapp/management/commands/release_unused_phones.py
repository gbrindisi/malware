import logging

from django.core.management import BaseCommand

from smsapp import commands


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    def handle(self, *args, **options):
        commands.cleanup_rented_phones()
