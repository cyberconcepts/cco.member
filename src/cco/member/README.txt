======================================================================
cco.member - cyberconcepts.org: member registration and authentication
======================================================================

  >>> from zope.publisher.browser import TestRequest

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
