from django import template
from django.conf import settings
from django.utils.safestring import mark_safe
from django_countries import conf
from django.template import Node
import pycountry

try:
    from urllib import parse as urlparse
except ImportError:
    import urlparse  # Python 2

register = template.Library()


@register.simple_tag
def is_active(request, pattern):
    import re

    if re.search(pattern, request.path):
        return 'active'
    return ''


@register.simple_tag
def is_phone_available(request, phone):
    """
    @type request: django.http.request.HttpRequest
    @type phone: PhoneData
    """
    if phone.owner_id is not None and request.user.id != phone.owner_id:
        return " disabled='1'"
    return ""


@register.simple_tag
def is_phone_owner_by_user(request, phone):
    """
    @type request: django.http.request.HttpRequest
    @type phone: PhoneData
    """
    if request.user.id == phone.owner_id:
        return ' checked="1"'
    return ''


@register.simple_tag
def is_phone_locked(request, phone):
    """
    @type request: django.http.request.HttpRequest
    @type phone: PhoneData
    """
    if phone.locked:
        return ' checked="1"'
    return ''


@register.filter
def country_code_to_name(code):
    """
    Returns country name from its code
    @param code: Country 2-letters code
    @type code: str
    @return: Country full name
    @rtype: str
    """
    try:
        country = pycountry.countries.get(alpha2=code)
        if country:
            return country.name
    except KeyError:
        return code
    return ""


@register.filter
def country_code_to_flag(code):
    """
    Returns country flag HTML code from country's code
    @param code: Country 2-letters code
    @type code: str
    @return: HTML code to render
    @rtype: str
    """
    # # todo: flags for unknown countries
    fmt = conf.Settings.COUNTRIES_FLAG_URL
    if code:
        url = fmt.format(code_upper=code, code=code.lower())
        uu = urlparse.urljoin(settings.STATIC_URL, url)
        return mark_safe('<img src="{0}"/>'.format(uu))
    return ""


class PrettyPrintNode(Node):
    def __init__(self, nodelist):
        self.nodelist = nodelist

    def render(self, context):
        from bs4 import BeautifulSoup

        html = BeautifulSoup(self.nodelist.render(context))
        return html.prettify()


@register.tag()
def pretty(parser, token):
    nodelist = parser.parse(('endpretty',))
    parser.delete_first_token()
    return PrettyPrintNode(nodelist)
