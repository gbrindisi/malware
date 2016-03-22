import cgi
from datetime import datetime

from django import template
from django.utils.safestring import mark_safe

from smsapp import models


register = template.Library()


@register.filter
def card_holder(card):
    try:
        return card['billing address']['first name'] + ' ' + card['billing address']['last name']
    except KeyError:
        try:
            return card['billing address']['name on card']
        except KeyError:
            return ""


@register.filter
def card_address(card):
    return card['billing address']['street address']


@register.filter
def card_zip(card):
    return card['billing address']['zip code']


@register.filter
def card_city(card):
    return card['billing address']['city']


@register.filter
def card_country(card):
    return card['billing address']['country']


@register.filter
def card_phone(card):
    return card['billing address']['phone']


@register.filter
def form_dialog_name(data):
    dlg_id = data.get('correlation id')
    if dlg_id is None:
        dlg_id = data.get('cor_id')
    try:
        dlg = models.RemoteDialog.objects.get(pk=dlg_id)
    except models.RemoteDialog.DoesNotExist:
        return ""
    return dlg.description


@register.filter
def named_field(data, field):
    return data.get(field) or ''


@register.filter
def form_id(data):
    return data['_id']


def print_items(dictObj, indent=0):
    p = ['<ul class="list-group">\n']
    for k, v in iter(sorted(dictObj.iteritems())):
        k_esc = cgi.escape(k.encode('utf-8', 'xmlcharrefreplace')) if isinstance(k, basestring) else k
        if isinstance(v, dict):
            p.append('<li class="list-group-item">{0} : '.format(k_esc))
            p.append(print_items(v))
            p.append('</li>')
        else:
            v = cgi.escape(v.encode('utf-8', 'xmlcharrefreplace')) if isinstance(v, basestring) else v
            p.append('<li class="list-group-item">{0} : {1}'.format(k_esc, v))
    p.append('</ul>\n')
    return '\n'.join(p)


@register.filter
def form_print(data):
    return mark_safe(print_items(data, 4))


@register.filter
def print_card_info(data):
    card = data['card']['number']
    card = card.replace(' ', '')[:6]
    try:
        r = models.BinData.objects.get(cid=card)
        source = r.bank[:10] if r.bank else None
        return "{0};{1};{2};{3}".format(source or "", r.ctype or "", r.clevel or "", r.country or "")
    except models.BinData.DoesNotExist:
        return ""


@register.filter
def print_card_info_full(data):
    card = data['card']['number']
    card = card.replace(' ', '')[:6]
    try:
        r = models.BinData.objects.get(cid=card)
        source = r.bank or None
        return "{0};{1};{2};{3}".format(source or "", r.ctype or "", r.clevel or "", r.country or "")
    except models.BinData.DoesNotExist:
        return ""


@register.filter
def remove_spaces(sss):
    return sss.replace(' ', '') if sss else ""


@register.filter("timestamp")
def timestamp(value):
    try:
        return datetime.fromtimestamp(value)
    except AttributeError:
        return ''