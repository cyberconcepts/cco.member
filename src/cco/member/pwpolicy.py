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
Check passwords for conformance to password policy.
"""


def checkPassword(pw):
    if len(pw) < 8:
        return False
    safety = dict(upper=False, lower=False, nonalpha=False)
    for c in pw:
        if ord(c) > 128:
            return False
        if c.isupper():
            safety['upper'] = True
        elif c.islower():
            safety['lower'] = True
        else:
            safety['nonalpha'] = True
    return False not in safety.values()
