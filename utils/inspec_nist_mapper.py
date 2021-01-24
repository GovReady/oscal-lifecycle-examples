#!/usr/bin/env python3

import json
import logging
import os
import sys
from pprint import pprint


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


if __name__ == '__main__':
    # Collate a component InSpec profile around NIST controls

    # Instantiate InSpecMapper for a component
    inspec_cmpt = InSpecMapper('heimdall/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile.json')
    # Collate the `control` content by NIST 800-53 tags
    nist_800_53_tag_map = inspec_cmpt.map_controls_by_tags('nist')

    # Hardcode output file path
    converted_path = 'conversions/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile-to-800-53-controls.json'

    # Dump conversion to file
    with open(converted_path, "w") as outfile: 
        json.dump(nist_800_53_tag_map, outfile, indent=4, sort_keys=True) 

    print("converted "+inspec_cmpt.profile_path+" to "+converted_path)
   
    # Here is how to see a mapping
    # pprint(nist_800_53_tag_map['AC-10'])
