# hal-provisioner

This is a simple VM provisioner/package installer/security hardener script written in bash that I am using to extend my skills into DevOps, Linux Administration, and scripting.

Workflow as follows:

Either launch `sc-provisioner.sh` via terminal and follow the prompts, or with the `--non-interactive` flag alongside all parameters:

* --non-interactive    Run in non-interactive mode (requires all parameters set)
* --cloud <provider>   Cloud provider (azure/aws/gcp)
* --name <vm-name>     VM name
* --region <region>    Region
* --user <username>    Admin username
* --ssh-key <path>     SSH public key path
* --ssh-port <port>    Custom SSH port
* --ssh-cidr <cidr>    Allowed SSH CIDR
* --packages <file>    Package list file (default: packages.txt)
* --no-hardening      Skip security hardening
* --help              Show this help

Afterwards, hal-provisioner will spool up a VM using the given parameters, harden its security posture (if selected), and install packages according to the package list.

---

See goals and future changes in issues.
