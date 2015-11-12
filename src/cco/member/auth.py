#
#  Copyright (c) 2015 Helmut Merz helmutm@cy55.de
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
import urllib
from zope.app.component import hooks
from zope.interface import Interface, implements
from zope import component
from zope.pluggableauth.plugins.session import SessionCredentialsPlugin \
                            as BaseSessionCredentialsPlugin
from zope.pluggableauth.plugins.session import SessionCredentials
from zope.publisher.interfaces.http import IHTTPRequest
from zope.session.interfaces import ISession
from zope.traversing.browser import absoluteURL
from zope.traversing.namespace import view

from loops.browser.node import getViewConfiguration
from loops.organize.interfaces import IPresence


class AuthURLNameSpace(view):

    def traverse(self, name, ignored):
        self.request.shiftNameToApplication()
        # ignore, has already been evaluated by credentials plugin
        return self.context


class TwoFactorSessionCredentials(SessionCredentials):

    def __init__(self, login, password):
        self.login = login
        self.password = password
        self.tan = random.randint(10000000, 99999999)
        self.timestamp = datetime.now()
        rng = range(8)
        self.tanA = random.choice(rng)
        rng.remove(self.tanA)
        self.tanB = random.choice(rng)
        self.hash = (hashlib.
                        sha224("%s:%s:%s" % (login, password, self.tan)).
                        hexdigest())
        self.validated = False


class SessionCredentialsPlugin(BaseSessionCredentialsPlugin):

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
            authMethod = traversalStack[-1][8:]
            #request.setTraversalStack(traversalStack[:-1])
        #viewAnnotations = request.annotations.setdefault('loops.view', {})
        #viewAnnotations['auth_method'] = authMethod
        print '***', authMethod
        #return super(SessionCredentialsPlugin, self).extractCredentials(request)
        if authMethod == 'standard':
            return self.extractStandardCredentials(
                            login, password, session, credentials)
        elif authMethod == '2factor':
            return self.extract2FactorCredentials(
                            login, password, session, credentials)
        else:
            return None

    def extractStandardCredentials(self, login, password, session, credentials):
        if login and password:
            credentials = SessionCredentials(login, password)
        if credentials:
            sessionData = session['zope.pluggableauth.browserplugins']
            sessionData['credentials'] = credentials
        else:
            return None
        return {'login': credentials.getLogin(),
                'password': credentials.getPassword()}

    def extract2FactorCredentials(self, login, password, session, credentials):
        return None

    def challenge(self, request):
        if not IHTTPRequest.providedBy(request):
            return False
        site = hooks.getSite()
        #camefrom = request.getURL() # wrong when object is not viewable
        #camefrom = request.getApplicationURL() + request['PATH_INFO']
        path = request['PATH_INFO'].split('/++/')[-1] # strip virtual host stuff
        if not path.startswith('/'):
            path = '/' + path
        camefrom = request.getApplicationURL() + path
        if 'login' in camefrom:
            camefrom = '/'.join(camefrom.split('/')[:-1])
        url = '%s/@@%s?%s' % (absoluteURL(site, request),
                              self.loginpagename,
                              urllib.urlencode({'camefrom': camefrom}))
        request.response.redirect(url)
        return True

    def logout(self, request):
        presence = component.getUtility(IPresence)
        presence.removePresentUser(request.principal.id)
        super(SessionCredentialsPlugin, self).logout(request)

