#!/usr/bin/env python3
import json
import logging
import os

def load_inspec_profile(path):
    try:
        fd = open(path)
        data = json.loads(fd.read())
        return data

    except Exception as err:
        logging.error(str(err))
        return {}

def is_valid_profile(profile):
    try:
        if not profile.get('controls'):
            return False

        return True

    except Exception as err:
        logging.error(str(err))
        return False

def get_controls(profile):
    try:
        return profile.get('controls')
    
    except Exception as err:
        logging.error(str(err))
        return []

def map_controls_by_tags(controls, tag):
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
    profile_path = 'heimdall/canonical-ubuntu-16.04-lts-stig-baseline-inspec-profile.json'
    profile = load_inspec_profile(profile_path)

    if not is_valid_profile(profile):
        logging.error("Inspec profile is malformed, could not map controls!")
        sys.exit(1)

    controls = get_controls(profile)
    tag_map = map_controls_by_tags(controls, 'nist')
    return tag_map

if __name__ == '__main__':
    print(run())