from ansible.runner.return_data import ReturnData
from ansible.utils import template, parse_kv

from ansible import errors
from ansible import utils

import boto.kms
import boto.sts
import boto

from contextlib import contextmanager
from Crypto.Util import Counter
from Crypto.Cipher import AES
import base64
import json
import os

@contextmanager
def assume(account_id, assume_role):
    for name in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SECURITY_TOKEN', 'AWS_SESSION_TOKEN']:
        if name in os.environ and not os.environ[name]:
            del os.environ[name]

    try:
        conn = boto.sts.connect_to_region('ap-southeast-2')
    except boto.exception.NoAuthHandlerFound:
        raise Exception("Export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY before running this script (your aws credentials)")

    try:
        creds = conn.assume_role("arn:aws:iam::{0}:{1}".format(account_id, assume_role), "ansible_decryption")
    except boto.exception.BotoServerError as error:
        if error.status == 403:
            raise Exception("Not allowed to assume role\terror={0}".format(error.message))
        else:
            raise

    creds_dict = creds.credentials.to_dict()

    os.environ['AWS_ACCESS_KEY_ID'] = creds_dict["access_key"]
    os.environ['AWS_SECRET_ACCESS_KEY'] = creds_dict["secret_key"]
    os.environ['AWS_SECURITY_TOKEN'] = creds_dict["session_token"]
    os.environ['AWS_SESSION_TOKEN'] = creds_dict["session_token"]
    try:
        yield
    finally:
        for thing in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SECURITY_TOKEN", "AWS_SESSION_TOKEN"):
            if thing in os.environ:
                del os.environ[thing]

class ActionModule(object):

    TRANSFERS_FILES = False

    def __init__(self, runner):
        self.runner = runner

    def run(self, conn, tmp, module_name, module_args, inject, complex_args=None, **kwargs):
        args = parse_kv(module_args)
        environment = args.get('environment')
        account_id = args.get('account_id')
        assume_role = args.get('assume_role')

        for name, val in (("environment", environment), ("account_id", account_id), ("assume_role", assume_role)):
            if val is None:
                result = dict(failed=True, msg="No {0} specified".format(name))
                return ReturnData(conn=conn, comm_ok=True, result=result)

        source = template.template(self.runner.basedir, environment, inject)

        if '_original_file' in inject:
            source = utils.path_dwim_relative(inject['_original_file'], 'vars', source, self.runner.basedir)
        else:
            source = utils.path_dwim(self.runner.basedir, source)

        if os.path.exists(source):
            decrypted_data = {}
            data = json.load(open(source))

            with assume(account_id, assume_role):
                kms = boto.kms.connect_to_region('ap-southeast-2')

                for key, val in data.items():
                    data_key = kms.decrypt(base64.b64decode(val['key']))["Plaintext"]
                    content = base64.b64decode(val['content'])
                    counter = Counter.new(128)
                    decryptor = AES.new(data_key[:32], AES.MODE_CTR, counter=counter)
                    decrypted_data[key] = decryptor.decrypt(content)

                result = dict(ansible_facts=decrypted_data)
                return ReturnData(conn=conn, comm_ok=True, result=result)
        else:
            result = dict(failed=True, msg="Couldn't find secrets!", file=source)
            return ReturnData(conn=conn, comm_ok=True, result=result)

