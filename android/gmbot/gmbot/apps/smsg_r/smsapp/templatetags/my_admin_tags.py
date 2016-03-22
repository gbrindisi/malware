from django import template
from django.conf import settings
import pymongo

register = template.Library()


@register.assignment_tag
def hascrashreport(code):
    ts = settings.MONGO['extra_data'].find({'type': "crash report", "code": code})
    if ts.count():
        return True
    return False


@register.inclusion_tag('admin/smsapp/phonedata/crash_reports.html')
def show_reports(code):
    ts = settings.MONGO['extra_data'].find({'type': "crash report", "code": code}).sort('time', pymongo.DESCENDING)
    return {'reports': ts}
