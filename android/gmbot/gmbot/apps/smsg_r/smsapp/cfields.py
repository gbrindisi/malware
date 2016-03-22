# custom fields their widgets and utilities

from django import forms
from django.db import models


def get_countries_choices():
    from mobile_codes import _countries

    cl = _countries()
    r = [("", "---"), ]
    for c in cl:
        mcc = c[4]
        if mcc is None:
            continue
        if isinstance(mcc, tuple):
            mcc = ",".join(mcc)
        r.append((mcc, c[0]))
    return r


def get_operator_choices(cnt_code):
    """
    Get list of operators matching MCC(s)
    @param cnt_code: country code(s). May contain multiple values, separated by commas
    @type cnt_code: unicode
    @return: operators
    @rtype: dict
    """
    # noinspection PyProtectedMember
    from mobile_codes import operators

    mcc = cnt_code.split(',')
    ol = operators()
    r = []
    for e in ol:
        if e[0] in mcc:
            opname = e[2] if e[2] else e[3]
            r.append((e[0] + e[1], "{0} ({1})".format(opname, e[1])))
    r.sort(key=lambda tup: tup[1])
    return r


class OperatorWidget(forms.widgets.MultiWidget):
    def __init__(self, attrs=None):
        _widgets = (
            forms.widgets.Select(choices=get_countries_choices(), attrs={'class': 'form-control'}),
            forms.widgets.Select(choices=(), attrs={'class': 'form-control'}),
        )
        super(OperatorWidget, self).__init__(_widgets, attrs)

    def decompress(self, value):
        import re

        a = re.compile("^\d{5,}")
        if not value or not a.match(value):
            return [None, None]
        mcc = value[:3]
        return [mcc, value]

    def value_from_datadict(self, data, files, name):
        d = [widget.value_from_datadict(data, files, name + '_%s' % i) for i, widget in enumerate(self.widgets)]
        try:
            return d[1]
        except ValueError:
            return ""


class OperatorField(models.CharField):
    widget = OperatorWidget
