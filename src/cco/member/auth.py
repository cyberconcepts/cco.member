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

import urllib
from persistent import Persistent
from zope.app.component import hooks
from zope.app.container.contained import Contained
from zope.interface import Interface, implements
from zope.app.authentication.interfaces import IAuthenticatorPlugin
from zope.app.authentication.principalfolder import IInternalPrincipal
from zope.app.authentication.principalfolder import PrincipalInfo
from zope.app.principalannotation.interfaces import IPrincipalAnnotationUtility
from zope.app.security.interfaces import IAuthentication
from zope import component
from zope.pluggableauth.plugins.session import SessionCredentialsPlugin \
                            as BaseSessionCredentialsPlugin
from zope.publisher.interfaces.http import IHTTPRequest
from zope import schema
from zope.traversing.api import getParent
from zope.traversing.browser import absoluteURL
from zope.traversing.namespace import view

from loops.browser.node import getViewConfiguration
from loops.organize.interfaces import IPresence
from loops.util import _


class AuthURLNameSpace(view):

    def traverse(self, name, ignored):
        self.request.shiftNameToApplication()
        # ignore, has already been evaluated by credentials plugin
        return self.context


class SessionCredentialsPlugin(BaseSessionCredentialsPlugin):

    def extractCredentials(self, request):
        traversalStack = request.getTraversalStack()
        authMethod = 'standard'
        if traversalStack and traversalStack[-1].startswith('++auth++'):
            authMethod = traversalStack[-1][8:]
            viewAnnotations = request.annotations.setdefault('loops.view', {})
            viewAnnotations['auth_method'] = authMethod
            #request.setTraversalStack(traversalStack[:-1])
        print '***', authMethod
        return super(SessionCredentialsPlugin, self).extractCredentials(request)

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

