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
Interfaces for member registration, password change, etc.
"""

from zope.i18nmessageid import MessageFactory
from zope.interface import Interface
from zope import schema


_ = MessageFactory('cco.member')


class IPasswordChange(Interface):

    oldPassword = schema.Password(title=_(u'label_old_password'),
                    description=_(u'desc_old_password'),
                    required=True,)

    password = schema.Password(title=_(u'label_new_password'),
                    description=_(u'desc_new_password'),
                    required=True,)

    passwordConfirm = schema.Password(title=_(u'label_confirm_new_password'),
                    description=_(u'desc_confirm_new_password'),
                    required=True,)

    oldPassword.nostore = True
    password.nostore = True
    passwordConfirm.nostore = True


class IPasswordReset(Interface):

    username = schema.TextLine(title=_(u'label_username'),
                               description=_(u'desc_usernam'),
                               required=False,)

    password = schema.TextLine(title=_(u'label_new_password'),
                               description=_(u'desc_new_password'),
                               required=False,)

    username.nostore = True
    password.nostore = True
