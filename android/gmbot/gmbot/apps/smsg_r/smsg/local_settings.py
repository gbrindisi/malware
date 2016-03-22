import sys
import os

ADMINS = (
    ('Admin', 'admin@localhost'),
)

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'slempo',
        'USER': 'traff',
        'HOST': 'localhost',
        'PORT': '6432',
        'PASSWORD': '12345',
    }
}

REDIS_DB = 1
MONGO_DB = 'smsg'

# in memory test-only DB:
if 'test' in sys.argv:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': ':memory',
            'USER': '',
            'PASSWORD': '',
            'HOST': '',
            'PORT': '',
        },
    }
    REDIS_DB = 0
    MONGO_DB = 'test'

DEBUG = True

TEMPLATE_DEBUG = DEBUG

ALLOWED_HOSTS = ['localhost','127.0.0.1', '<YOUR SERVER ADDRESS>']
SECRET_KEY = '<YOUR SECRET KEY>'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': "%(levelname)s '%(asctime)s' PID:%(process)d[%(thread)d] %(pathname)s:+%(lineno)d %(message)s"
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
        'syslog':{
            'level': 'DEBUG',
            'class': 'logging.handlers.SysLogHandler',
            'formatter': 'verbose',
            'facility': 'local0',
            'address': '/dev/log',
        },
    },
    'loggers': {
        'django.db.backends': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False
        },
        'smsapp': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False
        },
    },
}


STATIC_ROOT = '/var/www/vhosts/smsg/content/static'
MEDIA_ROOT = '/var/www/vhosts/smsg/content/media'
TIME_ZONE = 'Europe/Moscow'


