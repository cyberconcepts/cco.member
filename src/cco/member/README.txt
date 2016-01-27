======================================================================
cco.member - cyberconcepts.org: member registration and authentication
======================================================================

  >>> from zope.publisher.browser import TestRequest
  >>> from logging import getLogger
  >>> log = getLogger('cco.member.auth')

  >>> from loops.setup import addAndConfigureObject, addObject
  >>> from loops.concept import Concept
  >>> from loops.common import adapted

  >>> concepts = loopsRoot['concepts']
  >>> len(list(concepts.keys()))
  10

  >>> from loops.browser.node import NodeView
  >>> home = loopsRoot['views']['home']
  >>> homeView = NodeView(home, TestRequest())


Session Credentials Plug-in with optional 2-factor authentication
=================================================================

  >>> from cco.member.auth import SessionCredentialsPlugin
  >>> scp = SessionCredentialsPlugin()

When retrieving credentials for a standard request we get the usual
login + password dictionary.

  >>> input = dict(login='scott', password='tiger')
  >>> req = TestRequest(home, form=input)

  >>> scp.extractCredentials(req)
  {'login': 'scott', 'password': 'tiger'}

When the URL contains an authentication method reference to the 2-factor
authentication the first phase of the authentication (redirection to
TAN entry form) is executed.

  >>> req.setTraversalStack(['++auth++2factor'])

  >>> scp.extractCredentials(req)
  '2fa_tan_form.html?a=...&h=...&b=...'

What if we enter data for authentication phase 2? No authentication
because the hashes don't match.

  >>> input = dict(hash='#dummy#', tan_a='1', tan_b='2')
  >>> req = TestRequest(home, form=input)
  >>> req.setTraversalStack(['++auth++2factor'])

  >>> scp.extractCredentials(req)


Password Policy Checking
========================

  >>> from cco.member.pwpolicy import checkPassword

  >>> checkPassword(u'Test123')
  False
  >>> checkPassword(u'TestTest')
  False
  >>> checkPassword(u'tesT1234')
  True


Password Change Form
====================

  >>> from cco.member.browser import PasswordChange

