#!/usr/bin/env python3
#
# Copyright The Mbed TLS Contributors
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This script generates a file called _identifiers that contains all Mbed TLS
identifiers found on internal headers. This is the equivalent of what was
previously `list-identifiers.sh --internal`, and is useful for generating an
exclusion file list for ABI/API checking, since we do not promise compatibility
for them.

It uses the NameCeck class from check_names.py to perform the parsing.

Returns 0 on success, 1 if there is a script error.
Must be run from Mbed TLS root.
"""

import argparse
import logging
import traceback
import sys
from check_names import CodeParser

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "This script writes a list of parsed identifiers in internal "
            "headers to \"_identifiers\". This is useful for generating a list "
            "of names to exclude from ABI checking. "))

    parser.parse_args()

    try:
        name_check = CodeParser(logging.getLogger())
        result = name_check.parse_identifiers([
            "include/mbedtls/*_internal.h",
            "library/*.h"
        ])

        identifiers = ["{}\n".format(match.name) for match in result]
        with open("_identifiers", "w", encoding="utf-8") as f:
            f.writelines(identifiers)

    except Exception: # pylint: disable=broad-except
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
