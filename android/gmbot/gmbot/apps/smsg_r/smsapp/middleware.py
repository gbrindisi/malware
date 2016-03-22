from .models import SysUser


def app_context_processor(request):
    """
    @type request: HttpRequest
    """
    if request.user.id is None:
        return {}
    try:
        SysUser.objects.get(pk=request.user.id)
        return {'IS_SYSUSER': True, 'SITE_NAME': "GM BOT"}
    except SysUser.DoesNotExist:
        return {'IS_SYSUSER': False}
