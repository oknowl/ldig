#!/usr/bin/env python3
# Link Digger - ldig.py
# Copyright (C) 2022 oknowl, opensourcerer

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# =========================================================================================================================================================
# logging
import logging
from sys import version, version_info
from json import dumps as jsdumps
#from pprint import pformat


class log(logging.Logger):
    # Verbose v:
    # 0 Nothoing
    # 1 Error
    # 2 Warning (default)
    # 3 Info
    # 4 Debug

    def __init__(self, v=2):
        super().__init__('[+]')
        #self = logging.getLogger('[+]')
        self.DEBUG("Python version")
        self.DEBUG(version)
        self.DEBUG("Version info.")
        self.DEBUG(version_info)

    def DEBUG(self, msg):
        if isinstance(msg, str):
            self.debug("\t\t" + msg + "...")
        else:
            self.debug("\t\t" + jsdumps(msg, indent=4) + "...")

    def INFO(self, msg):
        if isinstance(msg, str):
            self.info("\t\t" + msg + "...")
        else:
            self.info("\t\t" + jsdumps(msg, indent=4) + "...")

    def __call__(self, msg):
        self.INFO(msg)

    def ENABLE_LOGS(self):
        self.setLevel(logging.INFO)
        loggers = [
            (name)
            for name in logging.root.manager.loggerDict
            if name.startswith("trafilatura")]
        for i in loggers:
            logging.getLogger(i).setLevel(logging.WARNING)

    def ENABLE_DEBUG(self):
        self.setLevel(logging.DEBUG)
        loggers = [
            (name)
            for name in logging.root.manager.loggerDict
            if name.startswith("trafilatura")]
        for i in loggers:
            logging.getLogger(i).setLevel(logging.INFO)

    def DISABLE_LOGS(self):
        self.setLevel(logging.CRITICAL)
        loggers = [
            (name)
            for name in logging.root.manager.loggerDict
            if name.startswith("trafilatura")]
        for i in loggers:
            logging.getLogger(i).setLevel(logging.CRITICAL)
