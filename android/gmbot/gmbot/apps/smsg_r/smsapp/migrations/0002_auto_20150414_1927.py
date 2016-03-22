# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('smsapp', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='AppDialog',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('description', models.CharField(max_length=255)),
                ('html_contents', models.TextField(null=True, verbose_name='HTML contents', blank=True)),
                ('apps', models.TextField(help_text='1 package per line', verbose_name='app filter')),
            ],
            options={
                'verbose_name': 'application dialog',
                'verbose_name_plural': 'application dialogues',
            },
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='dlg2',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='dlg3',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='is_html',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w1',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w1_repeated',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w1_repeated_text',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w2',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w2_enabled',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w2_repeated',
        ),
        migrations.RemoveField(
            model_name='remotedialog',
            name='w2_repeated_text',
        ),
        migrations.AddField(
            model_name='phonedata',
            name='app_dialogues_version',
            field=models.CharField(max_length=255, null=True, blank=True),
        ),
        migrations.AddField(
            model_name='phonedata',
            name='forwarding_calls',
            field=models.CharField(max_length=24, null=True, verbose_name='Forwarding calls to', blank=True),
        ),
    ]
