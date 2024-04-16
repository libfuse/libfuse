#!/usr/bin/env python3

"""
@file cppcheck_parse.py
@brief Script for parsing cppcheck XML files

@copyright
                               --- WARNING ---

     This work contains trade secrets of DataDirect Networks, Inc.  Any
     unauthorized use or disclosure of the work, or any part thereof, is
     strictly prohibited. Any use of this work without an express license
     or permission is in violation of applicable laws.

@copyright DataDirect Networks, Inc. CONFIDENTIAL AND PROPRIETARY
@copyright DataDirect Networks Copyright, Inc. (c) 2021-2024. All rights reserved.
"""
import argparse
import xml.etree.ElementTree as ET

def parseXML(xmlfile, verbose, print_defect_count):
    """Parse the cppcheck XML file and report the defect count"""
    ndefect = 0

    tree = ET.parse(xmlfile)

    root = tree.getroot()

    for child in root:
        if child.tag == "errors":
            for cpperr in child:
                cpperr_id = cpperr.attrib['id']

                if cpperr_id == "unmatchedSuppression":
                    continue
                if cpperr_id == "uninitMemberVar":
                    continue
                if cpperr_id == "premium-invalidLicense":
                    continue

                ndefect = ndefect + 1
                cpperr_sev = cpperr.attrib['severity']
                cpperr_file = ""
                cpperr_line = 0
                for loc in cpperr:
                    cpperr_file = loc.attrib['file']
                    cpperr_line = loc.attrib['line']
                if verbose:
                    str_out = f'{cpperr_file}:{cpperr_line} error={cpperr_id} severity={cpperr_sev}'
                    print(str_out)

    if print_defect_count:
        print(ndefect)

def main():
    """Main entry point for cppcheck XML processing"""
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", nargs="?", const="./cppcheck.xml", help="cppcheck XML result file")
    parser.add_argument("-c", "--count", action='store_true', help="print defect count")
    parser.add_argument("-v", "--verbose", action='store_true', help="print cppcheck defects")
    args = parser.parse_args()

    cppcheck_file = "./cppcheck.xml"
    if args.file:
        cppcheck_file = args.file

    parseXML(cppcheck_file, args.verbose, args.count)

if __name__ == "__main__":
    main()
