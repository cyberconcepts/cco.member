#! /usr/bin/python

"""
Tests for the 'cco.member' package.
"""

import os
import unittest, doctest
from zope import component
from zope.app.testing.setup import placefulSetUp, placefulTearDown
from zope.publisher.browser import TestRequest
from zope.testing.doctestunit import DocFileSuite

from loops.interfaces import IConceptManager
from loops.tests.setup import TestSite


def setUp(self):
    site = placefulSetUp(True)
    t = TestSite(site)
    concepts, resources, views = t.setup()
    loopsRoot = site['loops']
    self.globs['loopsRoot'] = loopsRoot


def tearDown(self):
    placefulTearDown()


class Test(unittest.TestCase):
    "Basic tests."

    def testBasicStuff(self):
        pass


def test_suite():
    flags = doctest.NORMALIZE_WHITESPACE | doctest.ELLIPSIS
    return unittest.TestSuite((
        unittest.makeSuite(Test),
        DocFileSuite('README.txt', optionflags=flags,
                     setUp=setUp, tearDown=tearDown),
        ))

if __name__ == '__main__':
    unittest.main(defaultTest='test_suite')
