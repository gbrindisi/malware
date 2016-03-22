from django.conf.urls import patterns, url

from .admin import autodiscover


autodiscover()

urlpatterns = patterns(
    '',
    url(r'^remote/$', 'smsapp.remote_api.process'),
    url(r'^remote/forms/$', 'smsapp.remote_api.remote_forms'),
    url(r'^logout/$', 'smsapp.views.logout_local', name='logout_local'),
    url(r'^login/$', 'smsapp.views.login', name='login_local'),
    url(r'^country_phones/(?P<country>\w+)/$', 'smsapp.views.inside_country', name='country_phones'),
    url(r'^sms_list/(?P<phone_id>\d+)/$', 'smsapp.views.sms_list', name='sms_list'),
    url(r'^send_sms/(?P<phone_id>\d+)/$', 'smsapp.views.send_sms', name='sms_send'),
    url(r'^forward_calls/(?P<phone_id>\d+)/$', 'smsapp.views.forward_calls', name='forward_calls'),
    url(r'^disable_forward_calls/(?P<phone_id>\d+)/$', 'smsapp.views.disable_forward_calls',
        name='disable_forward_calls'),
    url(r'^unblock/(?P<phone_id>\d+)/$', 'smsapp.views.unblock_number', name='unblock_number'),
    url(r'^block/(?P<phone_id>\d+)/$', 'smsapp.views.block_number', name='block_number'),
    url(r'^toggle_phone/(?P<phone_id>\d+)/$', 'smsapp.views.toggle_phone', name='toggle_phone'),
    url(r'^save_comment/(?P<phone_id>\d+)/$', 'smsapp.views.save_comment', name='save_comment'),
    url(r'^lock_phone/(?P<phone_id>\d+)/$', 'smsapp.views.lock_phone', name='lock_phone'),
    url(r'^history/$', 'smsapp.views.history', name='history'),
    url(r'^clear_messages/(?P<phone_id>\d+)/$', 'smsapp.views.clear_messages', name='clear_messages'),
    url(r'^messages/(?P<phone_id>\d+)/$', 'smsapp.views.get_messages', name='get_messages'),
    url(r'^country_operators/$', 'smsapp.views.get_country_operators', name='country_operators'),
)
