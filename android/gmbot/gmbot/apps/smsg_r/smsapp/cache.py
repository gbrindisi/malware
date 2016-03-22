from django.conf import settings

from smsapp import models


KEY_NAME = "blacklist"


def rebuild_cache():
    opt, created = models.Option.objects.get_or_create(name="blacklist")
    c = opt.content
    r = c.splitlines()
    pipe = settings.REDIS.pipeline(transaction=True)
    pipe.delete(KEY_NAME)
    for ln in filter(None, r):
        ss = ln.strip().lower()
        if ss:
            pipe.sadd(KEY_NAME, ss)
    pipe.execute()


def is_blacklisted(name):
    """
    Checks if the app is blacklisted
    @param name: app to check
    @type name: str
    @return: True if blacklisted, False otherwise
    @rtype: bool
    """
    return settings.REDIS.sismember(KEY_NAME, name.lower())
