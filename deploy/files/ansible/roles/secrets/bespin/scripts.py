"""
Use this via bespin.

So ./deploy/bespin.sh generate_secrets dev
"""

from bespin.actions import an_action

from Crypto.Util import Counter
from Crypto.Cipher import AES

from delfick_error import UserQuit
from six.moves import input
import boto.rds
import readline
import logging
import getpass
import base64
import glob
import json
import os

log = logging.getLogger("ansible_secrets")

here = os.path.abspath(os.path.dirname(__file__))
vars_folder = os.path.join(here, "..", "vars")

def __bespin__(bespin, task_maker):
    task_maker("generate_secret", "Generate a secret", no_assume_role=True).specify_stack('app')
    task_maker("generate_secrets", "Generate all the secrets", no_assume_role=True).specify_stack('app')
    task_maker("generate_missing_secrets", "Generate the missing secrets", no_assume_role=True).specify_stack('app')

@an_action(needs_stack=True)
def generate_secret(collector, stack, secret_key=None, **kwargs):
    if 'libedit' in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
    readline.set_completer(NoneCompleter)

    stack.bespin.set_credentials()
    stack.bespin.credentials.assume_role = collector.configuration["secret_vars"]["role"]

    environment = collector.configuration["environment"]
    secret_vars = collector.configuration["secret_vars"]["keys"]
    key_id = collector.configuration["environments"][environment]["vars"]["KMSMasterKey"]

    if secret_key is None:
        print("Which key do you wish to encrypt a new value for?")
        print("\n".join("{0}. {1}".format(index+1, key) for index, key in enumerate(secret_vars)))
        while True:
            number = input("Number: ")
            if not number.isdigit() or int(number) < 0 or int(number) > len(secret_vars):
                print("Please choose a valid number!")
            else:
                secret_key = secret_vars[int(number)-1]
                print("Ok, modifying {0}".format(secret_key))
                break
    else:
        print("")
        print("=" * 80)
        print("Make key for {0}".format(secret_key))

    stack.bespin.credentials.verify_creds()

    while True:
        answer = input("Is the secret in a file?[n]: ")
        if answer is "":
            answer = "n"
        if answer not in ("y", "yes", "yeah", "n", "no", "nup"):
            print("Please say yes or no!")
        else:
            is_file = answer in ("y", "yes", "yeah")
            break

    if is_file:
        while True:
            location = filename_prompt("Location of the secret: ")
            if not os.path.exists(location):
                print("Sorry, that location doesn't exist!")
            else:
                with open(location, "rb") as fle:
                    secret = fle.read()
                break
    else:
        secret = getpass.getpass("The new value: ")

    if not os.path.exists(vars_folder):
        os.makedirs(vars_folder)

    secrets_location = os.path.join(vars_folder, environment)
    if not os.path.exists(secrets_location):
        secrets = {}
    else:
        try:
            secrets = json.load(open(secrets_location))
        except (ValueError, TypeError) as error:
            log.error("Failed to open secrets\terror=%s", error)
            secrets = {}

    if secret_key not in secrets:
        secrets[secret_key] = {}

    kms = stack.kms.conn
    result = kms.generate_data_key(key_id, key_spec="AES_256")
    secrets[secret_key]["key"] = base64.b64encode(result['CiphertextBlob']).decode('utf-8')
    plaintext = result["Plaintext"]

    counter = Counter.new(128)
    encryptor = AES.new(plaintext[:32], AES.MODE_CTR, counter=counter)
    encrypted = encryptor.encrypt(secret)

    secrets[secret_key]["content"] = base64.b64encode(encrypted).decode('utf-8')
    json.dump(secrets, open(secrets_location, 'w'), indent=4)
    print("Secret for {0} has been written to {1}".format(secret_key, secrets_location))

@an_action(needs_stack=True)
def generate_secrets(collector, stack, **kwargs):
    secret_vars = collector.configuration["secret_vars"]["keys"]
    for key in secret_vars:
        generate_secret(collector, stack, secret_key=key, **kwargs)

@an_action(needs_stack=True)
def generate_missing_secrets(collector, stack, **kwargs):
    secret_vars = collector.configuration["secret_vars"]["keys"]
    if not os.path.exists(vars_folder):
        os.makedirs(vars_folder)

    environment = collector.configuration['environment']
    secrets_location = os.path.join(vars_folder, environment)
    if not os.path.exists(secrets_location):
        secrets = {}
    else:
        try:
            secrets = json.load(open(secrets_location))
        except (ValueError, TypeError) as error:
            log.error("Failed to open secrets\terror=%s", error)
            secrets = {}

    current_keys = secrets.keys()
    for key in secret_vars:
        if key not in current_keys:
            generate_secret(collector, stack, secret_key=key, **kwargs)

class NoneCompleter(object):
    def complete(self, text, state):
        self.matches = []
        return None

class FilenameCompleter(object):
    def complete(self, text, state):
        text = readline.get_line_buffer()
        if not text:
            self.matches = glob.glob("*")
        else:
            if os.path.isfile(text):
                self.matches = []

            else:
                dirname = os.path.dirname(text)
                if not dirname:
                    self.matches = glob.glob("*")
                else:
                    self.matches = glob.glob(os.path.join(dirname, "*"))

            self.matches = [os.path.basename(match) for match in self.matches if match.startswith(text)]

        if len(self.matches) > state:
            if len(self.matches) == 1:
                if os.path.isdir(os.path.join(os.path.dirname(text), self.matches[state])):
                    return "{0}/".format(self.matches[state])
            return self.matches[state]
        else:
            return None

def custom_prompt(msg, delims="", completer=lambda: None):
    """Start up a prompt that with particular delims and completer"""
    try:
        orig_delims = readline.get_completer_delims()
        orig_completer = readline.get_completer()

        readline.set_completer_delims(delims)
        readline.set_completer(completer)

        try:
            ret = input(msg)
        finally:
            readline.set_completer_delims(orig_delims)
            readline.set_completer(orig_completer)

        return ret
    except EOFError:
        raise UserQuit()

def filename_prompt(msg, delims="/"):
    completer = FilenameCompleter().complete
    return custom_prompt(msg, delims, completer)

