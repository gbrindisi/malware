from django.conf import settings


FMT_QUEUE_NAME = "queue:{0}"


def has_commands(uniq_id):
    """
    Checks if commands are in the queue for the given phone
    @param uniq_id: Phone ID
    @type uniq_id: str
    @return: True is there are commands in the queue
    @rtype: bool
    """
    return settings.REDIS.llen(FMT_QUEUE_NAME.format(uniq_id)) > 0


def add_command(uniq_id, user, cmd):
    """
    Adds command to the queue
    @param uniq_id: Phone ID
    @type uniq_id: basestring
    @param user: User performing the command
    @type user: User or None
    @param cmd: Command to add
    @type cmd: basestring
    """
    settings.REDIS.rpush(FMT_QUEUE_NAME.format(uniq_id), cmd)


def get_next_command(uniq_id):
    """
    Return next command for the phone ID
    @param uniq_id: ID of the phone to check
    @type uniq_id: str
    @return: A command to process client-side
    @rtype: str or None
    """
    vv = settings.REDIS.lpop(FMT_QUEUE_NAME.format(uniq_id))
    return vv if vv is None else vv.decode('UTF-8')
