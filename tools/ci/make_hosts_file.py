# mypy: allow-untyped-defs

import argparse
import os
import logging

from ..localpaths import repo_root

from ..serve.serve import build_config, make_hosts_file


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("address", default="127.0.0.1", nargs="?",
                        help="Address that hosts should point at")
    return parser


def run(**kwargs):
    config_path = os.path.join(repo_root, "config.json")
    # ugly patch to pass my subdomains to the config builder

    logger = logging.getLogger()
    
    try:
        with open(config_path, "r") as f:
            try:
                subdoms = json.loads(f.read())["subdomains"]
            except:
                subdoms = None


        if subdoms:
            config_builder = build_config(logger, override_path=config_path, ssl={"type": "none"}, subdomains=subdoms)
        else:
            config_builder = build_config(logger, override_path=config_path, ssl={"type": "none"})
            

        with config_builder as config:
            print(make_hosts_file(config, kwargs["address"]))
    except:
        config_builder = build_config(logger, override_path=config_path, ssl={"type": "none"})
        with config_builder as config:
            print(make_hosts_file(config, kwargs["address"]))
