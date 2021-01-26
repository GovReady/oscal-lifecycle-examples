#!/usr/bin/env python3

# Usage:
#   # Run from root directory of oscal-lifecycle-examples b/c of hardcoded values
#   python utils/inspec_nist_mapper.py
#
# Authors:
#   AJ Stein, Greg Elin
#   2021
#
# Notes:
#   Hardcoded file paths for input and output

from argparse import ArgumentParser
import json
import logging
import os
import sys
from pprint import pprint
import datetime

LOGFORMAT = os.environ.get("LOGFORMAT", "%(levelname)2s %(message)s")
LOGROOT = os.environ.get("LOGROOT", "root")
LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
SELF_PATH = os.environ.get("SELF_PATH", os.path.dirname(os.path.abspath(__file__)))
logging.basicConfig(format=LOGFORMAT)
logger = logging.getLogger(LOGROOT)
logger.setLevel(level=LOGLEVEL)


class InSpecMapper():
    """A class to map a MITRE Heimdall project component InSpec profile to other formats"""

    def __init__(self, profile_path=None):

        try:
            if profile_path is None:
                print('InSpecMapper requires path to InSpec profile file.')
            self.profile_path = profile_path

            # Read a component InSpec profile created from a STIG by MITRE Heimdall project
            self.profile = self.load_inspec_profile(self.profile_path)

            # Check if component InSpec profile has `control` block, is "valid"
            if not self.is_valid_profile(self.profile):
                logging.error("Inspec profile is malformed, could not map controls!")
                sys.exit(1)

            # We are only interested in the granular `controls`
            self.controls = self.get_controls(self.profile)

            # TODO: Get components name
            # Set components name
            # self.cmpt_name = ?????????

        except Exception as err:
            logging.error(str(err))

    def load_inspec_profile(self, path):
        """Load a MITRE Heimdall projectcomponent InSpec profile created from a STIG"""

        try:
            fd = open(path)
            data = json.loads(fd.read())
            return data
        except Exception as err:
            logging.error(str(err))
            return {}

    def is_valid_profile(self, profile):
        """Confirm InSpec profile has control block"""

        try:
            if not profile.get('controls'):
                return False

            return True
        except Exception as err:
            logging.error(str(err))
            return False

    def get_controls(self, profile):
        """Get granular STIG controls from InSpec profile"""

        try:
            return profile.get('controls')
        except Exception as err:
            logging.error(str(err))
            return []

    def map_controls_by_tags(self, tag):
        """Group/collate STIG controls around NIST 800-53 control tags"""

        tag_map = {}

        try:
            for c in self.controls:
                t = c.get('tags').get('nist')[0]
                if not tag_map.get(t): tag_map[t] = []
                tag_map[t].append(c)

            return tag_map
        except Exception as err:
            logging.error(str(err))
            return {}

    def generate_jsonl_statements(self, tag="nist"):
        """Returns an array of JSON objects where each object equates to a control (e.g. mapped tag) statement"""

        try:
            json_l_statements = []
            tag_map = self.map_controls_by_tags(tag)
            # TODO: sort by key!
            for control_id, stig_rule_list in tag_map.items():
                combined_stig_rule_desc_list = [stig_rule['desc'].replace("\n"," ") for stig_rule in stig_rule_list]
                json_l_statements.append(json.dumps(dict(control_id=control_id, text="\n\n".join(combined_stig_rule_desc_list))))
            return json_l_statements
        except Exception as err:
            logging.error(str(err))
            return []

    def generate_combined_statements(self, cmpt_name="My Component", tag="nist"):
        """Returns JSON object in GovReady "combined" format that can be "oscalized" into a OSCAL component model"""

        # Set metadata
        # Partially hardcoded for the moment...
        catalog = "NIST_SP-800-53_rev4"
        source = "Heimdall InSPec Profile from STIG"
        remarks = "Upstream source content is Heimdall InSpec Profile for component using oscal-lifecycle-examples/utils/inspect_nist_mapper.py"
        created = datetime.datetime.now().isoformat()
        command = "inspect_nist_mapper.py"

        # Create combined object
        combined = {
            "components": {
                cmpt_name: {
                    catalog: {}
                }
            },
            "metadata": [
                {
                    "source": source,
                    "catalog": catalog,
                    "remarks": remarks,
                    "created": created,
                    "command": command
                }
            ]
        }

        # Add the statements to components
        components = {}

        try:
            tag_map = self.map_controls_by_tags(tag)
            # TODO: sort by key!
            for control_id, stig_rule_list in tag_map.items():
                # TODO: Add each rule as its own statement in the combined file.
                combined_stig_rule_desc_list = [stig_rule['desc'].replace("\n"," ") for stig_rule in stig_rule_list]
                combined['components'][cmpt_name][catalog][control_id] = [dict(text="\n\n".join(combined_stig_rule_desc_list), source=source)]
            return combined
        except Exception as err:
            logging.error(str(err))
            return []

def run():
    """
    A utility function to parse runtime arguments and run common InspecMapper
    operations in a way that will be callable from the CLI or an additional
    Python library.
    """
    parser = ArgumentParser(
        description="An example Inspec mapper class for mapping into GovReady's 'OSCALized' JSON format.")
    parser.add_argument("-i", "--inspec-profile", required=False, dest="inspec_path",
                        help="Path to the input Inspec profile",
                        default='heimdall/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile.json')

    args, rest = parser.parse_known_args()

    logger.debug(f"args: {args}")
    logger.debug(f"rest: {rest}")
    config = vars(args)

    # Collate a component InSpec profile around NIST controls

    # Instantiate InSpecMapper for a component
    inspec_cmpt = InSpecMapper('heimdall/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile.json')
    inspect_cmpt_name = "Ubuntu 16.04 LTS"

    # Collate the `control` content by NIST 800-53 tags
    nist_800_53_tag_map = inspec_cmpt.map_controls_by_tags('nist')

    # Hardcoded output file path
    converted_path = 'conversions/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile-to-800-53-controls.json'

    # Dump conversion to JSON collated around nist tags to file
    with open(converted_path, "w") as outfile:
        json.dump(nist_800_53_tag_map, outfile, indent=4, sort_keys=True)
    print("converted "+inspec_cmpt.profile_path+" to "+converted_path)

    # Hardcoded output file path
    converted_path = 'conversions/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile-to-800-53-controls-govready-json-l.txt'
    # Dump conversion to json-l format that GovReady uses in a oscalizing pipeline to a file
    with open(converted_path, "w") as outfile:
        # outfile.write(line + '\n' for line in "\nkinspec_cmpt.generate_jsonl_statements('nist'))
        for item in inspec_cmpt.generate_jsonl_statements('nist'):
            outfile.write(item+"\n")
    print("converted "+inspec_cmpt.profile_path+" to "+converted_path)

    # Convert to GovReady combined file format, precursor to oscalization
    nist_800_53_tag_map = inspec_cmpt.generate_combined_statements(inspect_cmpt_name, 'nist')
    # Hardcoded output file path
    converted_path = 'conversions/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile-to-800-53-controls-govready-combined.json'
    # Dump conversion to json-l format that GovReady uses in a oscalizing pipeline to a file
    with open(converted_path, "w") as outfile:
        json.dump(nist_800_53_tag_map, outfile, indent=4, sort_keys=True)
    print("converted "+inspec_cmpt.profile_path+" to "+converted_path)



    # Here is how to see a mapping
    # pprint(nist_800_53_tag_map['AC-10'])


if __name__ == '__main__':
    run()
