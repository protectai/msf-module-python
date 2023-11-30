#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-python-modules.html

# standard modules
import logging

# extra modules
dependencies_missing = False
try:
    import requests
except ImportError:
    dependencies_missing = True

from metasploit import module


metadata = {
    'name': 'Python RCE Module Example',
    'description': '''
        Python Metasploit RCE Module
    ''',
    'authors': [
        'byt3bl33d3r <marcello@protectai.com>'
    ],
    'date': '2018-03-22',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'url', 'ref': 'https://huntr.com/blog/'},
        {'type': 'aka', 'ref': 'Coldstone'},
        {'type': 'cve', 'ref': 'CVE-420-69'}
    ],
    'type': 'remote_exploit_cmd_stager',
    'targets': [
        {'platform': 'linux', 'arch': 'aarch64'},
        {'platform': 'linux', 'arch': 'x64'},
        {'platform': 'linux', 'arch': 'x86'}
    ],
    'payload': {
        'command_stager_flavor': 'wget'
    },
    'options': {
        'command': {'type': 'string', 'description': 'The command to execute', 'required': True, 'default': 'echo "Hello from Metasploit"'},
        'rhost': {'type': 'address', 'description': 'Target address', 'required': True, 'default': None},
        'rport': {'type': 'port', 'description': 'Target port (TCP)', 'required': True, 'default': 80},
        'ssl': {'type': 'bool', 'description': 'Negotiate SSL/TLS for outgoing connections', 'required': True, 'default': False}
    }
}

def convert_args_to_correct_type(args):
    '''
    Utility function to correctly "cast" the modules options to their correct types according to the options.

    When a module is run using msfconsole, the module args are all passed as strings through the JSON-RPC so we need to convert them manually.
    I'd use pydantic but want to avoid extra deps.
    '''

    corrected_args = {}

    for k,v in args.items():
        option_to_convert = metadata['options'].get(k)
        if option_to_convert:
            type_to_convert = metadata['options'][k]['type']
            if type_to_convert == 'bool':
                if isinstance(v, str):
                    if v.lower() == 'false':
                        corrected_args[k] = False
                    elif v.lower() == 'true':
                        corrected_args[k] = True

            if type_to_convert == 'port':
                corrected_args[k] = int(v)

    return {**args, **corrected_args}

def run(args):
    args = convert_args_to_correct_type(args)

    module.LogHandler.setup(msg_prefix=f"{args['rhost']} - ")
    if dependencies_missing:
        logging.error('Module dependency (requests) is missing, cannot continue')
        return

    base_url = f"{'https' if args['ssl'] else 'http'}://{args['rhost']}:{args['rport']}"

    # Your code here
    try:
        r = requests.get(base_url, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error('{}'.format(e))
        return

    logging.info('{}...'.format(r.text[0:50]))


if __name__ == '__main__':
    module.run(metadata, run)
