#!/usr/bin/env python3
import json
import logging
import os
from pprint import pprint


def load_inspec_profile(path):
    """Load a component inSpec profile created from a STIG by MITRE Heimdall project"""

    try:
        fd = open(path)
        data = json.loads(fd.read())
        return data
    except Exception as err:
        logging.error(str(err))
        return {}

def is_valid_profile(profile):
    """Confirm inSpec profile has control block"""

    try:
        if not profile.get('controls'):
            return False

        return True
    except Exception as err:
        logging.error(str(err))
        return False

def get_controls(profile):
    """Get granular STIG controls from inSpec profile"""

    try:
        return profile.get('controls')
    except Exception as err:
        logging.error(str(err))
        return []

def map_controls_by_tags(controls, tag):
    """Group/collate STIG controls around NIST 800-53 control tags"""

    tag_map = {}

    try:
        for c in controls:
            t = c.get('tags').get('nist')[0]
            if not tag_map.get(t): tag_map[t] = []
            tag_map[t].append(c)

        return tag_map
    except Exception as err:
        logging.error(str(err))
        return {}

def run():

    # Read a component inSpec profile created from a STIG by MITRE Heimdall project
    profile_path = 'heimdall/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile.json'
    profile = load_inspec_profile(profile_path)

    # Check if component inSpec profile has `control` block, is "valid"
    if not is_valid_profile(profile):
        logging.error("Inspec profile is malformed, could not map controls!")
        sys.exit(1)

    # We are only interested in the granular `controls` 
    controls = get_controls(profile)
    # Collate the `control` content by NIST 800-53 tags
    tag_map = map_controls_by_tags(controls, 'nist')
    return tag_map

if __name__ == '__main__':
    # Collate a component inSpec profile around NIST controls

    # Hardcode output file path
    converted_path = 'conversions/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile-to-800-53-controls.json'
    cmpt = run()

    # dump conversion to file
    with open(converted_path, "w") as outfile: 
        json.dump(cmpt, outfile, indent=4, sort_keys=True) 

    # pprint(cmpt['AC-10'])
    # pprint(run())
