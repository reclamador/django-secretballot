# -*- coding: utf-8 -*-
from hashlib import md5


class SecretBallotMiddleware(object):
    def process_request(self, request):
        request.secretballot_token = self.generate_token(request)

    def generate_token(self, request):
        raise NotImplementedError


class SecretBallotIpMiddleware(SecretBallotMiddleware):
    def generate_token(self, request):
        return request.META['REMOTE_ADDR']


class SecretBallotIpUseragentMiddleware(SecretBallotMiddleware):
    def generate_token(self, request):
        addr = request.META['REMOTE_ADDR']
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        s = "".join((addr, user_agent))
        try:
            # If s is a unicode string, this will work (Python3)
            s = s.encode('utf-8')
        except UnicodeDecodeError:
            # Otherwise, s will raise a 'UnicodeDecodeError', meaning s
            # is probably an already encoded string (Python2)
            # We decode it and encode it again, to ensure it uses UTF-8
            s = s.decode('utf-8').encode('utf-8')

        return md5(s).hexdigest()
