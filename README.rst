Secrets Ansible
===============

This is what is required to use the secrets ansible role.

* Copy deploy/files/ansible/roles/secrets into your ansible roles folder
* Modify deploy/aws/bespin.yml to include the bespin.extra_imports line
* Modify deploy/files/ansible/ansible.cfg to include the action_plugins from the
  secrets role
* Modify deploy/aws/app.json to have the parameters and vars.yml entries in
  app.json
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
