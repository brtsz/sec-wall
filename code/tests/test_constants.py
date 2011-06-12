# -*- coding: utf-8 -*-

"""
Copyright (C) 2010 Dariusz Suchojad <dsuch at gefira.pl>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

# stdlib
import re
from uuid import uuid4

# nose
from nose.tools import assert_true, eq_

def test_constants():
    """ Makes sure the number of constants defined is as expected and there
    are no duplicates amongst them.
    """
    _locals = {}
    _globals = {}

    exec 'from secwall.constants import *' in _globals, _locals

    expected = 19

    eq_(len(_locals), expected)
    eq_(len(set(_locals.values())), expected)
