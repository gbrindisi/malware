#!/bin/sh

. /home/admin/virtualenv/django/bin/activate

cd /home/admin/apps/smsg_r
python manage.py check_inactive
python manage.py check_sentid_sms
python manage.py clean_logs
