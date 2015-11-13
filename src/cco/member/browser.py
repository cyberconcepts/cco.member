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
Login, logout, unauthorized stuff.
"""

from zope.app.exception.browser.unauthorized import Unauthorized as DefaultUnauth
from zope.app.pagetemplate import ViewPageTemplateFile
from zope.app.security.interfaces import IAuthentication
from zope.app.security.interfaces import ILogout, IUnauthenticatedPrincipal
from zope.cachedescriptors.property import Lazy
from zope import component
from zope.interface import implements
from zope.publisher.interfaces.http import IHTTPRequest

from loops.browser.concept import ConceptView
from loops.browser.node import NodeView, getViewConfiguration


template = ViewPageTemplateFile('auth.pt')


class LoginConcept(ConceptView):

    @Lazy
    def macro(self):
        return template.macros['login_form']


class LoginForm(NodeView, LoginConcept):

    @Lazy
    def item(self):
        return self


class TanForm(LoginForm):

    @Lazy
    def macro(self):
        return template.macros['tan_form']


class Logout(object):

    implements(ILogout)

    def __init__(self, context, request):
        self.context = context
        self.request = request

    def __call__(self):
        nextUrl = self.request.get('nextURL') or self.request.URL[-1]
        if not IUnauthenticatedPrincipal.providedBy(self.request.principal):
            auth = component.getUtility(IAuthentication)
            ILogout(auth).logout(self.request)
        return self.request.response.redirect(nextUrl)


class Unauthorized(ConceptView):

    isTopLevel = True

    def __init__(self, context, request):
        self.context = context
        self.request = request

    def __call__(self):
        response = self.request.response
        response.setStatus(403)
        # make sure that squid does not keep the response in the cache
        response.setHeader('Expires', 'Mon, 26 Jul 1997 05:00:00 GMT')
        response.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate')
        response.setHeader('Pragma', 'no-cache')
        if self.nodeView is None:
            v = DefaultUnauth(self.context, self.request)
            return v()
        url = self.nodeView.topMenu.url
        response.redirect(url + '/unauthorized')
