from uwsgidecorators import timer

from smsapp import cache


@timer(5)
def update_caches(signum):
    cache.rebuild_cache()
