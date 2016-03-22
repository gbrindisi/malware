from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.dispatch import dispatcher
from django.db.models import signals

"""
    Registers any number of custom permissions that are not related to any
    certain model (i.e. "global/app level").

    You must pass the models module of your app as the sender parameter. If you
    use "None" instead, the permissions will be duplicated for each application
    in your project.

    Permissions is a tuple:
       (
           # codename, name
           ("can_drive", "Can drive"),
           ("can_drink", "Can drink alcohol"),
       )

    Examples:
        from myapp.mysite import models as app
        register_custom_permissions(('my_perm', 'My Permission'), app)
        register_custom_permissions(('my_perm', 'My Permission'), sys.modules[__name__])  # in models.py
        register_custom_permissions(('my_perm', 'My Permission'))
"""


def register_custom_permissions(permissions, sender):
    def mk_permissions(permissions, app, verbosity):
        # retrieve actual appname string from module instance
        appname = app.__name__.lower().split('.')[-2]
        # create a content type for the app
        ct, created = ContentType.objects.get_or_create(model='', app_label=appname,
                                                        defaults={'name': appname})
        if created and verbosity >= 2: print "Adding custom content type '%s'" % ct
        # create permissions
        for codename, name in permissions:
            p, created = Permission.objects.get_or_create(codename=codename,
                                                          content_type__pk=ct.id,
                                                          defaults={'name': name, 'content_type': ct})
            if created and verbosity >= 2:
                print "Adding custom permission '%s'" % p

    dispatcher.connect(lambda app, verbosity: mk_permissions(permissions, app, verbosity),
                       sender=sender, signal=signals.post_syncdb, weak=False)


"""
    A wrapper around register_custom_permissions() that automatically determines
    the sender paramter via the stack. This is probably overkill, but learning
    about stack inspection in python was very interesting, so here it is.

    The functions expects that it is called from a module within your django
    application directory (e.g. project.app.callermodule). If that is not the
    case, you can use the levels_down parameter: If __name__ is
    project.app.views.callermodule, then levels_down should be set to 2
    (because "callermodule" is two levels below the application directory).
"""


def register_custom_permissions_simple(permissions, levels_down=1):
    # find the caller's __name__ via the stack
    import inspect, sys

    frame = inspect.stack()[1][0]
    try:
        caller__name__ = frame.f_locals['__name__']
    finally:
        del frame
    # build the path to the app's models.py
    models_module = '.'.join(caller__name__.split('.')[0:-levels_down] + ['models'])
    sender = sys.modules[models_module]
    # register the signal handler
    register_custom_permissions(permissions, sender)

