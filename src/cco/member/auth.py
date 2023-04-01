#
#  Copyright (c) 2023 Helmut Merz helmutm@cy55.de
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#

"""
Specialized authentication components.
"""

import hashlib
import logging
import random
from datetime import datetime, timedelta
from email.MIMEText import MIMEText
from urllib import urlencode
import requests

from zope.app.component import hooks
from zope.interface import Interface, implements
from zope import component
from zope.pluggableauth.interfaces import IAuthenticatedPrincipalFactory
from zope.pluggableauth.plugins.session import SessionCredentialsPlugin \
                            as BaseSessionCredentialsPlugin
from zope.pluggableauth.plugins.session import SessionCredentials
from zope.publisher.interfaces.http import IHTTPRequest
from zope.session.interfaces import ISession
from zope.traversing.browser import absoluteURL
from zope.traversing.namespace import view

from loops.browser.node import getViewConfiguration
from loops.organize.interfaces import IPresence
from loops.organize.party import getAuthenticationUtility
from loops.util import _

try:
    from config import single_sign_on as sso
except ImportError:
    sso = None


TIMEOUT = timedelta(minutes=60)
#PRIVKEY = "6LcGPQ4TAAAAABCyA_BCAKPkD6wW--IhUicbAZ11"   # for captcha
log = logging.getLogger('cco.member.auth')


class AuthURLNameSpace(view):

    def traverse(self, name, ignored):
        self.request.shiftNameToApplication()
        # ignore, has already been evaluated by credentials plugin
        return self.context


class TwoFactorSessionCredentials(SessionCredentials):

    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.tan = random.randint(100000, 999999)
        self.timestamp = datetime.now()
        rng = range(len(str(self.tan)))
        t1 = random.choice(rng)
        rng.remove(t1)
        t2 = random.choice(rng)
        self.tanA, self.tanB = sorted((t1, t2))
        self.hash = (hashlib.
                        sha224("%s:%s:%s" % (login, password, self.tan)).
                        hexdigest())
        self.validated = False


class SessionCredentialsPlugin(BaseSessionCredentialsPlugin):

    tan_a_field = 'tan_a'
    tan_b_field = 'tan_b'
    hash_field = 'hash'

    def extractCredentials(self, request):
        if not IHTTPRequest.providedBy(request):
            return None
        login = request.get(self.loginfield, None)
        password = request.get(self.passwordfield, None)
        session = ISession(request)
        sessionData = session.get('zope.pluggableauth.browserplugins')
        traversalStack = request.getTraversalStack()
        authMethod = 'standard'
        credentials = None
        if sessionData:
            credentials = sessionData.get('credentials')
            if isinstance(sessionData, TwoFactorSessionCredentials):
                authMethod = '2factor'
        if (authMethod == 'standard' and
                traversalStack and traversalStack[-1].startswith('++auth++')):
            ### SSO: do not switch to 2factor if logged-in via sso
            if not getattr(credentials, 'sso_source', None):
                authMethod = traversalStack[-1][8:]
        viewAnnotations = request.annotations.setdefault('loops.view', {})
        viewAnnotations['auth_method'] = authMethod
        #log.info('authentication method: %s.' % authMethod)
        if authMethod == 'standard':
            return self.extractStandardCredentials(
                            request, login, password, session, credentials)
        elif authMethod == '2factor':
            return self.extract2FactorCredentials(
                            request, login, password, session, credentials)
        else:
            return None

    def extractStandardCredentials(self, request, login, password,
                                   session, credentials):
        if login and password:
            credentials = SessionCredentials(login, password)
        sso_source = request.get('sso_source', None)
        credentials.sso_source = sso_source
        if credentials:
            sessionData = session['zope.pluggableauth.browserplugins']
            ### SSO: do not overwrite existing credentials on sso login
            if not sessionData.get('credentials') or sso_source is None: 
                sessionData['credentials'] = credentials
        else:
            return None
        login = credentials.getLogin()
        password = credentials.getPassword()
        ### SSO: send login request to sso.targetUrls
        if sso_source is None:
            sso_send_login(login, password)
        return dict(login=login, password=password)

    def extract2FactorCredentials(self, request, login, password,
                                  session, credentials):
        tan_a = request.get(self.tan_a_field, None)
        tan_b = request.get(self.tan_b_field, None)
        hash = request.get(self.hash_field, None)
        if (login and password) and not (tan_a or tan_b or hash):
            return self.processPhase1(request, session, login, password)
        if (tan_a and tan_b and hash) and not (login or password):
            credentials = self.processPhase2(request, session, hash, tan_a, tan_b)
        if credentials and credentials.validated:
            login = credentials.getLogin()
            password = credentials.getPassword()
            ### SSO: send login request to sso.targetUrls
            sso_source = request.get('sso_source', None)
            if sso_source is None:
                sso_send_login(login, password)
            return dict(login=login, password=password)
        return None

    def processPhase1(self, request, session, login, password):
        sessionData = session['zope.pluggableauth.browserplugins']
        credentials = TwoFactorSessionCredentials(login, password)
        sessionData['credentials'] = credentials
        # send email
        log.info("Processing phase 1, TAN: %s. " % credentials.tan)
        params = dict(h=credentials.hash,
                      a=credentials.tanA+1, b=credentials.tanB+1)
        url = self.getUrl(request, '2fa_tan_form.html', params)
        return request.response.redirect(url, trusted=True)

    def processPhase2(self, request, session, hash, tan_a, tan_b):
        def _validate_tans(a, b, creds):
            tan = str(creds.tan)
            return tan[creds.tanA] == a and tan[creds.tanB] == b
        sessionData = session['zope.pluggableauth.browserplugins']
        credentials = sessionData.get('credentials')
        if not credentials:
            msg = 'Missing credentials'
            return log.warn(msg)
        log.info("Processing phase 2, TAN: %s. " % credentials.tan)
        if credentials.hash != hash:
            msg = 'Illegal hash.'
            return log.warn(msg)
        if credentials.timestamp < datetime.now() - TIMEOUT:
            msg = 'Timeout exceeded.'
            request.form['loops.message'] = msg
            return log.warn(msg)
        if not _validate_tans(tan_a, tan_b, credentials):
            msg = 'TAN digits not correct.'
            log.warn(msg)
            params = dict(h=credentials.hash,
                          a=credentials.tanA+1, b=credentials.tanB+1)
            params['loops.message'] = msg
            url = self.getUrl(request, '2fa_tan_form.html', params)
            request.response.redirect(url, trusted=True)
            return None
        credentials.validated = True
        log.info('Credentials valid.')
        sessionData['credentials'] = credentials
        if request.get('camefrom'):
            request.response.redirect(request['camefrom'])
        return credentials

    def getUrl(self, request, action, params):
        if request.get('camefrom'):
            params['camefrom'] = request['camefrom']
        baseUrl = request.get('base_url') or ''
        if baseUrl and not baseUrl.endswith('/'):
            baseUrl += '/'
        return '%s%s?%s' % (baseUrl, action, urlencode(params))

    def challenge(self, request):
        if not IHTTPRequest.providedBy(request):
            return False
        site = hooks.getSite()
        path = request['PATH_INFO'].split('/++/')[-1] # strip virtual host stuff
        if not path.startswith('/'):
            path = '/' + path
        camefrom = request.getApplicationURL() + path
        if 'login' in camefrom:
            camefrom = '/'.join(camefrom.split('/')[:-1])
        url = '%s/@@%s?%s' % (absoluteURL(site, request),
                              self.loginpagename,
                              urlencode({'camefrom': camefrom}))
        request.response.redirect(url)
        return True

    def logout(self, request):
        presence = component.getUtility(IPresence)
        presence.removePresentUser(request.principal.id)
        super(SessionCredentialsPlugin, self).logout(request)


def getCredentials(request):
    session = ISession(request)
    sessionData = session.get('zope.pluggableauth.browserplugins')
    if not sessionData:
        return None
    return sessionData.get('credentials')


def getPrincipalFromCredentials(context, request, credentials):
    if not credentials:
        return None
    cred = dict(login=credentials.getLogin(),
                password=credentials.getPassword())
    auth = getAuthenticationUtility(context)
    authenticatorPlugins = [p for n, p in auth.getAuthenticatorPlugins()]
    for authplugin in authenticatorPlugins:
        if authplugin is None:
            continue
        info = authplugin.authenticateCredentials(cred)
        if info is None:
            continue
        info.authenticatorPlugin = authplugin
        principal = component.getMultiAdapter((info, request),
            IAuthenticatedPrincipalFactory)(auth)
        principal.id = auth.prefix + info.id
        return principal

def getPrincipalForUsername(username, context, request):
    auth = getAuthenticationUtility(context)
    authenticatorPlugins = [p for n, p in auth.getAuthenticatorPlugins()]
    for authplugin in authenticatorPlugins:
        if authplugin is None:
            continue
        info = authplugin.get(username)
        if info is None:
            continue
        info.authenticatorPlugin = authplugin
        principal = info
        #principal = component.getMultiAdapter((info, request),
        #    IAuthenticatedPrincipalFactory)(auth)
        principal.id = authplugin.prefix + info.login
        return principal

def sso_send_login(login, password):
    if not sso:
        return
    data = dict(login=login, password=password, sso_source=sso.get('source', ''))
    for url in sso['targets']:
        resp = requests.post(url, data)
        log.info('sso_login - url: %s, login: %s -> %s %s.' % (
            url, login, resp.status_code, resp.text))
