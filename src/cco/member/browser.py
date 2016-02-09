#
#  Copyright (c) 2016 Helmut Merz helmutm@cy55.de
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

from email.MIMEText import MIMEText
from zope.app.exception.browser.unauthorized import Unauthorized as DefaultUnauth
from zope.app.pagetemplate import ViewPageTemplateFile
from zope.app.security.interfaces import IAuthentication
from zope.app.security.interfaces import ILogout, IUnauthenticatedPrincipal
from zope.cachedescriptors.property import Lazy
from zope import component
from zope.i18n import translate
from zope.i18nmessageid import MessageFactory
from zope.interface import implements
from zope.publisher.interfaces.http import IHTTPRequest
from zope.sendmail.interfaces import IMailDelivery

from cco.member.auth import getCredentials, getPrincipalFromCredentials
from cco.member.interfaces import IPasswordChange
from cco.member.pwpolicy import checkPassword
from cybertools.composer.schema.browser.common import schema_macros
from cybertools.composer.schema.browser.form import Form
from cybertools.composer.schema.schema import FormState, FormError
from loops.browser.concept import ConceptView
from loops.browser.node import NodeView, getViewConfiguration
from loops.common import adapted
from loops.organize.interfaces import IMemberRegistrationManager
from loops.organize.party import getPersonForUser


_ = MessageFactory('cco.member')

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

    @Lazy
    def credentials(self):
        return getCredentials(self.request)

    def sendTanEmail(self):
        if self.credentials is None:
            return None
        person = None
        principal = getPrincipalFromCredentials(
                            self.context, self.request, self.credentials)
        if principal is not None:
            person = adapted(getPersonForUser(
                            self.context, self.request, principal))
        if person is None:     # invalid credentials
            # TODO: display message
            return None
        tan = self.credentials.tan
        recipient = person.email
        recipients = [recipient]
        lang = self.languageInfo.language
        subject = translate(_(u'tan_mail_subject'), target_language=lang)
        message = translate(_(u'tan_mail_text_$tan', mapping=dict(tan=tan)),
                            target_language=lang)
        senderInfo = self.globalOptions('email.sender')
        sender = senderInfo and senderInfo[0] or 'info@loops.cy55.de'
        sender = sender.encode('UTF-8')
        msg = MIMEText(message.encode('UTF-8'), 'plain', 'UTF-8')
        msg['Subject'] = subject.encode('UTF-8')
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)
        mailhost = component.getUtility(IMailDelivery, 'Mail')
        mailhost.send(sender, recipients, msg.as_string())
        return recipient


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
        if self.isAnonymous:
            response.redirect(url)
        else:
            response.redirect(url + '/unauthorized')


class PasswordChange(NodeView, Form):

    interface = IPasswordChange
    message = _(u'message_password_changed')

    formErrors = dict(
        confirm_nomatch=FormError(_(u'error_password_confirm_nomatch')),
        wrong_oldpw=FormError(_(u'error_password_wrong_oldpw')),
        invalid_pw=FormError(_(u'error_password_invalid_pw')),
    )

    label = label_submit = _(u'label_change_password')

    @Lazy
    def macro(self):
        return schema_macros.macros['form']

    @Lazy
    def item(self):
        return self

    @Lazy
    def data(self):
        return dict(oldPassword=u'', password=u'', passwordConfirm=u'')

    def update(self):
        form = self.request.form
        if not form.get('action'):
            return True
        formState = self.formState = self.validate(form)
        if formState.severity > 0:
            return True
        pw = form.get('password')
        if not checkPassword(pw):
            fi = formState.fieldInstances['password']
            fi.setError('invalid_pw', self.formErrors)
            formState.severity = max(formState.severity, fi.severity)
            return True
        pwConfirm = form.get('passwordConfirm')
        if pw != pwConfirm:
            fi = formState.fieldInstances['password']
            fi.setError('confirm_nomatch', self.formErrors)
            formState.severity = max(formState.severity, fi.severity)
            return True
        oldPw = form.get('oldPassword')
        regMan = IMemberRegistrationManager(self.loopsRoot)
        principal = self.request.principal
        result = regMan.changePassword(principal, oldPw, pw)
        if not result:
            fi = formState.fieldInstances['oldPassword']
            fi.setError('wrong_oldpw', self.formErrors)
            formState.severity = max(formState.severity, fi.severity)
            return True
        url = '%s?loops.message=%s' % (self.url, self.message)
        self.request.response.redirect(url)
        return False

    def validate(self, data):
        formState = FormState()
        for f in self.schema.fields:
            fi = f.getFieldInstance()
            value = data.get(f.name)
            fi.validate(value, data)
            formState.fieldInstances.append(fi)
            formState.severity = max(formState.severity, fi.severity)
        return formState

