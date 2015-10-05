Secrets Ansible
===============

We want to be able to store secrets in our git repository without storing it in
clear text in git.

To achieve this we use kms to encrypt values and we store the crypto text
instead.

Then, on the instance at ansible time we decrypt the crypto text using kms and
inject the resulting decrypted values as variables in the ansible.

This means we need to setup:

* A KMS Key for your project
* An decryptor role that has access to decrypt with the kms key
* An instance role that can assume role as the decryptor

Setting it up
-------------

This is what is required to use the secrets ansible role.

* Copy deploy/files/ansible/roles/secrets into your ansible roles folder
* Modify deploy/aws/bespin.yml to include the bespin.extra_imports line
* Modify deploy/files/ansible/ansible.cfg to include the action_plugins from the
  secrets role
* Add secrets as a role in deploy/files/ansible/playbook.yml
* Modify deploy/aws/app.json to have the parameters and vars.yml entries in
  app.json
* Remove AppServerRole and it's associated instance profile and role policies
  from deploy/aws/app.json and add the instance_profile to the LaunchConfiguration
* Modify deploy/aws/bespin.yml to include those parameters in params.yml
* Copy deploy/roles/encryption.yaml and deploy/roles/instance_role.yaml into
  your deploy/roles for each environment
* Run ./deploy/roles/iam_syncr for each deploy/roles environment
* Create a KMS key inside the rca-vpc repository and allow the instance role to
  decrypt, the decryptor role to decrypt and the encryptor role to encrypt. Add
  one per environment.
* Run ./deploy/roles/iam_syncr for each environment you added the kms key to
* Do a "aws kms list-aliases" and search for the Key id of your new KMS key
* Go back to the project and add the KMSMasterKey to your environment configs
* Change the secret_vars in bespin.yml to have the names of the secrets you
  want to store
* Run "./deploy/bespin.sh generate_secrets <environment>" for each environment
  and follow the prompts
* Commit and push your changes
