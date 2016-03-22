"""
Django settings for smsg project.

For more information on this file, see
https://docs.djangoproject.com/en/1.6/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.6/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

import redis


BASE_DIR = os.path.dirname(os.path.dirname(__file__))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.6/howto/deployment/checklist/

TEMPLATE_DIRS = (os.path.join(BASE_DIR, 'templates'),)

STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.sites',
    'django_extensions',
    'django_countries',
    'mobile_codes',
    'bootstrap3',
    'smsc',
    'smsapp',
    'django_admin_bootstrapped',
    'django.contrib.admin',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.core.context_processors.static",
    "django.contrib.messages.context_processors.messages",
    "django.core.context_processors.request",
    "smsapp.middleware.app_context_processor",
)

TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
    'django.template.loaders.eggs.Loader',
)

ROOT_URLCONF = 'smsg.urls'

WSGI_APPLICATION = 'smsg.wsgi.application'


# Internationalization
# https://docs.djangoproject.com/en/1.6/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.6/howto/static-files/

BOOTSTRAP3 = {
    'jquery_url': '/static/js/jquery-1.10.2.min.js ',
    'base_url': '/static/',
    'theme_url': 'bootstrap-theme.min.css',
}

LOGIN_URL = "/"
LOGOUT_URL = "/"
LOGIN_REDIRECT_URL = "/"

SOUTH_TESTS_MIGRATE = False
SKIP_SOUTH_TESTS = True

REDIS_HOST = "localhost"
REDIS_DB = 1
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_DB = "smsg"

# noinspection PyUnresolvedReferences
from decimal import Decimal

SMS_PRICE = Decimal('10')
POINTS_PER_BTC = Decimal('1000')
BTC_CONFIRMATIONS = 1
BTC_CONFIRMATIONS_BACKGROUND = 3

REGISTRATION_DOMAIN_CLASS = 'smsapp.models.SysUser'
ACCOUNT_ACTIVATION_DAYS = 3

from pymongo import MongoClient

SITE_ID = 1
DEFAULT_SENDID_PHONE = None

DAB_FIELD_RENDERER = 'django_admin_bootstrapped.renderers.BootstrapFieldRenderer'

# noinspection PyUnresolvedReferences
from .local_settings import *

REDIS = redis.Redis(host=REDIS_HOST, db=REDIS_DB)

MONGO_CONN = MongoClient(host=MONGO_HOST, port=MONGO_PORT)
MONGO = MONGO_CONN[MONGO_DB]

