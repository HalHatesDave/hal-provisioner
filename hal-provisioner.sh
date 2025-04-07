#!/usr/bin/env bash
################################################################################################################################
### hal-provisioner v3.1: a Multi-Cloud VM Provisioner (Azure/AWS/GCP)
################################################################################################################################
echo -e "\n\033[1;33m
/\\_/\\   ██╗  ██╗ █████╗ ██╗         /\\_/\\
( o.o )  ██║  ██║██╔══██╗██║        ( o.o )
> ^ <   ███████║███████║██║         > ^ <
/\\_/\\   ██╔══██║██╔══██║██║         /\\_/\\
( o.o )  ██║  ██║██║  ██║███████╗   ( o.o )
> ^ <   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    > ^ <
\033[0m"
echo "hal-provisioner v2.0 now running..."
sleep 1
################################################################################################################################
set -eo pipefail
################################################################################################################################
### Cloud Provider Selection
select_cloud_provider() {
  echo "Select cloud provider:"
  echo "1) Azure"
  echo "2) AWS"
  echo "3) GCP"
  read -p "Enter choice (1-3) [1]: " CLOUD_CHOICE
  CLOUD_CHOICE=${CLOUD_CHOICE:-1}

  case "$CLOUD_CHOICE" in
    1) CLOUD="azure" ;;
    2) CLOUD="aws" ;;
    3) CLOUD="gcp" ;;
    *) echo "Invalid choice. Using Azure by default."; CLOUD="azure" ;;
  esac

  echo "Selected cloud provider: $CLOUD"
}
################################################################################################################################
### Interactive Configuration
################################################################################################################################
get_vm_config() {
  # Default values based on cloud provider
  case "$CLOUD" in
    azure)
      DEFAULT_VM_NAME="devbox01"
      DEFAULT_REGION="eastus"
      DEFAULT_IMAGE="Ubuntu2204"
      DEFAULT_SIZE="Standard_B1s"
      ;;
    aws)
      DEFAULT_VM_NAME="devbox01"
      DEFAULT_REGION="us-east-1"
      DEFAULT_IMAGE="ami-0c55b159cbfafe1f0"  # Ubuntu 22.04 LTS
      DEFAULT_SIZE="t3.small"
      ;;
    gcp)
      DEFAULT_VM_NAME="devbox01"
      DEFAULT_REGION="us-central1"
      DEFAULT_IMAGE="ubuntu-2204-lts"
      DEFAULT_SIZE="e2-small"
      ;;
  esac

  # Get VM Name
  read -p "Name of the VM [$DEFAULT_VM_NAME]: " VM_NAME
  VM_NAME=${VM_NAME:-$DEFAULT_VM_NAME}

  # Get Region...
  while true; do
    read -p "Region to deploy VM [$DEFAULT_REGION]: " REGION
    REGION=${REGION:-$DEFAULT_REGION}

    # Basic validation - check if region is non-empty
    if [[ -z "$REGION" ]]; then
      echo "Error: Region cannot be empty. Please try again."
      continue
    fi

    # ...and validate
    case "$CLOUD" in
      azure)
        if ! az account list-locations --query "[].name" -o tsv | grep -q "^$REGION$"; then
          echo "Error: Invalid Azure region. Please try again."
          continue
        fi
        ;;
      aws)
        if ! aws ec2 describe-regions --region-names "$REGION" --query "Regions[0].RegionName" --output text &>/dev/null; then
          echo "Error: Invalid AWS region. Please try again."
          continue
        fi
        ;;
      gcp)
        if ! gcloud compute regions list --filter="name=$REGION" --format="value(name)" | grep -q "^$REGION$"; then
          echo "Error: Invalid GCP region. Please try again."
          continue
        fi
        ;;
    esac
    break
  done

  # Get desired image...
  while true; do
    case "$CLOUD" in
      azure)
        echo "Image for VM (e.g., 'Ubuntu2204', 'Canonical:UbuntuServer:18.04-LTS:latest') [$DEFAULT_IMAGE]: "
        ;;
      aws)
        echo "Image for VM (must be an AMI ID like 'ami-0c55b159cbfafe1f0' or name like 'ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*') [$DEFAULT_IMAGE]: "
        ;;
      gcp)
        echo "Image for VM (e.g., 'ubuntu-2204-lts', 'debian-11') [$DEFAULT_IMAGE]: "
        ;;
      *)
        echo "Image for VM [$DEFAULT_IMAGE]: "
        ;;
    esac

    read -p "> " IMAGE
    IMAGE=${IMAGE:-$DEFAULT_IMAGE}

    if [[ -z "$IMAGE" ]]; then
      echo "Error: Image cannot be empty. Please try again."
      continue
    fi

    # ...and validate with cloud provider
    case "$CLOUD" in
      azure)
        if ! az vm image list --all --location "$REGION" --query "[?contains(urn, '$IMAGE')].urn" -o tsv | grep -q .; then
          echo "Error: Image not found in Azure region $REGION. Please try again."
          echo "Tip: Try 'az vm image list --output table --location $REGION' to see available images"
          continue
        fi
        ;;
      aws)
        if [[ "$IMAGE" == ami-* ]]; then
          if ! aws ec2 describe-images --image-ids "$IMAGE" --region "$REGION" &>/dev/null; then
            echo "Error: AMI not found in AWS region $REGION. Please try again."
            echo "Tip: Try 'aws ec2 describe-images --owners amazon --region $REGION' to see available AMIs"
            continue
          fi
        else
          echo "Note: Searching for AMIs matching '$IMAGE'. For production use, specify exact AMI ID."
          # Don't validate name patterns immediately - we'll handle the search in create_vm_aws()
        fi
        ;;
      gcp)
        if ! gcloud compute images list --filter="name~'$IMAGE'" --format="value(name)" | grep -q .; then
          echo "Error: Image not found in GCP. Please try again."
          echo "Tip: Try 'gcloud compute images list' to see available images"
          continue
        fi
        ;;
    esac
    break
  done

  # Get VM Size...
  while true; do
    read -p "Size of VM [$DEFAULT_SIZE]: " SIZE
    SIZE=${SIZE:-$DEFAULT_SIZE}

    if [[ -z "$SIZE" ]]; then
      echo "Error: Size cannot be empty. Please try again."
      continue
    fi

    # ...and validate based on cloud provider
    case "$CLOUD" in
      azure)
        if ! az vm list-sizes --location "$REGION" --query "[?name=='$SIZE'].name" -o tsv | grep -q "^$SIZE$"; then
          echo "Error: Invalid VM size for Azure region $REGION. Please try again."
          continue
        fi
        ;;
      aws)
        if ! aws ec2 describe-instance-types --instance-types "$SIZE" --region "$REGION" &>/dev/null; then
          echo "Error: Invalid instance type for AWS region $REGION. Please try again."
          continue
        fi
        AWS_INSTANCE_TYPE="$SIZE"
        ;;
      gcp)
        if ! gcloud compute machine-types list --filter="name=$SIZE AND zone:$REGION" --format="value(name)" | grep -q "^$SIZE$"; then
          echo "Error: Invalid machine type for GCP region $REGION. Please try again."
          continue
        fi
        GCP_MACHINE_TYPE="$SIZE"
        ;;
    esac
    break
  done

  # Get Admin Username
  read -p "Admin username [adminuser]: " ADMIN_USER
  ADMIN_USER=${ADMIN_USER:-"adminuser"}

  # Get SSH Key Path
  read -p "SSH public key path [$HOME/.ssh/id_rsa.pub]: " SSH_KEY
  SSH_KEY=${SSH_KEY:-"$HOME/.ssh/id_rsa.pub"}

  # Get SSH Port
  while true; do
    read -p "SSH port [22]: " SSH_PORT
    SSH_PORT=${SSH_PORT:-22}

    if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 || "$SSH_PORT" -gt 65535 ]]; then
      echo "Error: Invalid SSH port. Must be between 1 and 65535."
      continue
    fi
    break
  done

  # Get Security Hardening preference
  read -p "Enable security hardening? (y/n) [y]: " HARDEN_CHOICE
  HARDEN_CHOICE=${HARDEN_CHOICE:-y}
  if [[ "$HARDEN_CHOICE" =~ ^[Yy]$ ]]; then
    SECURITY_HARDENING=true
  else
    SECURITY_HARDENING=false
  fi

  # Get Package File
  read -p "Package list file (leave empty to skip) [packages.txt]: " PACKAGE_FILE
  PACKAGE_FILE=${PACKAGE_FILE:-"packages.txt"}
}
################################################################################################################################
### Variable Storage Land
################################################################################################################################
CLOUD=""
VM_NAME=""
REGION=""
ADMIN_USER="adminuser"
SSH_KEY="$HOME/.ssh/id_rsa.pub"
IMAGE=""
SIZE=""
AWS_INSTANCE_TYPE=""
GCP_MACHINE_TYPE=""
RESOURCE_GROUP="provision-rg"
PACKAGE_FILE="packages.txt"
TAGS="Environment=Dev,Owner=Admin"
SECURITY_HARDENING=true
SSH_PORT=22
SSH_CIDR="$(curl -s --fail --connect-timeout 3 ifconfig.me || echo "0.0.0.0")/32"
################################################################################################################################
### Usage / Help Text
################################################################################################################################
usage() {
  echo "Usage: $0 [options]"
  echo "Options:"
  echo "  --non-interactive    Run in non-interactive mode (requires all parameters set)"
  echo "  --cloud <provider>   Cloud provider (azure/aws/gcp)"
  echo "  --name <vm-name>     VM name"
  echo "  --region <region>    Region"
  echo "  --user <username>    Admin username"
  echo "  --ssh-key <path>     SSH public key path"
  echo "  --ssh-port <port>    Custom SSH port"
  echo "  --ssh-cidr <cidr>    Allowed SSH CIDR"
  echo "  --packages <file>    Package list file"
  echo "  --no-hardening      Skip security hardening"
  echo "  --help              Show this help"
  exit 0
}

################################################################################################################################
### Basic Validation
################################################################################################################################
validate_inputs() {
  # Validate cloud provider
  case "$CLOUD" in
    azure|aws|gcp) ;;
    *) echo "[-] Invalid cloud provider. Use: azure, aws, gcp"; exit 1 ;;
  esac

  # Validate VM name
  if [[ -z "$VM_NAME" ]]; then
    echo "[-] VM name cannot be empty"
    exit 1
  fi

  # Validate region
  if [[ -z "$REGION" ]]; then
    echo "[-] Region cannot be empty"
    exit 1
  fi

  # Validate SSH key
  if [[ ! -f "$SSH_KEY" ]]; then
    echo "[-] SSH key not found: $SSH_KEY"
    exit 1
  fi

  # Validate package file if specified
  if [[ -n "$PACKAGE_FILE" && ! -f "$PACKAGE_FILE" ]]; then
    echo "[-] Package file not found: $PACKAGE_FILE"
    exit 1
  fi

  # Validate SSH port
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [[ "$SSH_PORT" -lt 1 || "$SSH_PORT" -gt 65535 ]]; then
    echo "[-] Invalid SSH port: $SSH_PORT"
    exit 1
  fi

  # Validate CIDR format
  if ! [[ "$SSH_CIDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    echo "[-] Invalid CIDR format: $SSH_CIDR"
    exit 1
  fi
}

################################################################################################################################
### CLI Tool Checker
################################################################################################################################
check_cli() {
  case "$CLOUD" in
    azure)
      command -v az &> /dev/null || { echo "[-] Azure CLI not found. Install from: https://aka.ms/install-az-cli"; exit 1; }
      az account show &> /dev/null || { echo "[-] Azure CLI not logged in. Run 'az login'"; exit 1; }
      ;;
    aws)
      command -v aws &> /dev/null || { echo "[-] AWS CLI not found. Install from: https://aws.amazon.com/cli/"; exit 1; }
      aws sts get-caller-identity &> /dev/null || { echo "[-] AWS CLI not configured. Run 'aws configure'"; exit 1; }
      ;;
    gcp)
      command -v gcloud &> /dev/null || { echo "[-] GCP CLI not found. Install from: https://cloud.google.com/sdk/docs/install"; exit 1; }
      gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q . || { echo "[-] GCP CLI not logged in. Run 'gcloud auth login'"; exit 1; }
      ;;
  esac
}

################################################################################################################################
### Cleanup Functions for Error Handling
################################################################################################################################
cleanup_azure() {
  echo "[!] Cleaning up Azure resources..."
  az group delete --name "$RESOURCE_GROUP" --yes --no-wait || true
}

cleanup_aws() {
  echo "[!] Cleaning up AWS resources..."
  # Find and terminate the instance
  INSTANCE_ID=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=$VM_NAME" --query "Reservations[].Instances[?State.Name!='terminated'].InstanceId" --output text)
  if [[ -n "$INSTANCE_ID" ]]; then
    aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" > /dev/null
    aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
  fi

  # Delete key pair
  aws ec2 delete-key-pair --key-name "$AWS_KEY_NAME" 2>/dev/null || true

  # Delete security group
  SG_ID=$(aws ec2 describe-security-groups --filters Name=group-name,Values="ssh-only-$VM_NAME" --query "SecurityGroups[0].GroupId" --output text)
  if [[ -n "$SG_ID" ]]; then
    aws ec2 delete-security-group --group-id "$SG_ID" 2>/dev/null || true
  fi
}

cleanup_gcp() {
  echo "[!] Cleaning up GCP resources..."
  gcloud compute instances delete "$VM_NAME" --zone="${REGION}-a" --quiet || true
  gcloud compute firewall-rules delete "allow-ssh-$VM_NAME" --quiet 2>/dev/null || true
}

################################################################################################################################
### Provisioner Functions
################################################################################################################################
# Azure
create_vm_azure() {
  echo "[+] Provisioning Azure VM..."

  # Create resource group (idempotent)
  az group create --name "$RESOURCE_GROUP" --location "$REGION" --tags $TAGS --output none

  # Create VM
  if ! az vm create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VM_NAME" \
    --image "$IMAGE" \
    --size "$SIZE" \
    --admin-username "$ADMIN_USER" \
    --ssh-key-values "$SSH_KEY" \
    --public-ip-sku Standard \
    --output none; then
    cleanup_azure
    exit 1
  fi

  # Configure NSG to restrict SSH access
  az network nsg rule create \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "${VM_NAME}NSG" \
    --name "allow-ssh" \
    --access Allow \
    --protocol Tcp \
    --direction Inbound \
    --priority 100 \
    --source-address-prefixes "$SSH_CIDR" \
    --source-port-ranges "*" \
    --destination-address-prefixes "*" \
    --destination-port-ranges "$SSH_PORT" \
    --output none

  PUBLIC_IP=$(az vm show -d -g "$RESOURCE_GROUP" -n "$VM_NAME" --query publicIps -o tsv)
}
################################################################################################################################
# AWS
create_vm_aws() {
  echo "[+] Provisioning AWS EC2 instance..."
  AWS_KEY_NAME="aws-key-${VM_NAME}-$(date +%s)"

  # Create key pair
  if ! aws ec2 import-key-pair --key-name "$AWS_KEY_NAME" --public-key-material "fileb://$SSH_KEY" > /dev/null; then
    exit 1
  fi

  # Create security group with more descriptive name
  SG_NAME="ssh-only-$VM_NAME"
  SG_ID=$(aws ec2 create-security-group --group-name "$SG_NAME" --description "SSH-only for $VM_NAME" --query "GroupId" --output text)

  # Add SSH rule to security group
  aws ec2 authorize-security-group-ingress \
    --group-id "$SG_ID" \
    --protocol tcp \
    --port "$SSH_PORT" \
    --cidr "$SSH_CIDR"

  # Determine AMI ID based on user input
  if [[ "$IMAGE" == ami-* ]]; then
    # User provided a direct AMI ID
    AMI_ID="$IMAGE"
    echo "[+] Using user-specified AMI: $AMI_ID"

    # Verify the AMI exists in this region
    if ! aws ec2 describe-images --image-ids "$AMI_ID" --region "$REGION" >/dev/null 2>&1; then
      echo "[-] Error: AMI $AMI_ID not found in region $REGION"
      cleanup_aws
      exit 1
    fi
  else
    # Try to find a matching AMI
    echo "[+] Searching for AMI matching: $IMAGE"

    # First try Ubuntu canonical
    AMI_ID=$(aws ec2 describe-images \
      --owners 099720109477 \
      --filters "Name=name,Values=*$IMAGE*" \
                "Name=architecture,Values=x86_64" \
                "Name=root-device-type,Values=ebs" \
                "Name=virtualization-type,Values=hvm" \
      --query "sort_by(Images, &CreationDate)[-1].ImageId" \
      --output text \
      --region "$REGION")

    # If not found, try community AMIs
    if [[ -z "$AMI_ID" ]]; then
      AMI_ID=$(aws ec2 describe-images \
        --executable-users all \
        --filters "Name=name,Values=*$IMAGE*" \
                  "Name=architecture,Values=x86_64" \
                  "Name=root-device-type,Values=ebs" \
                  "Name=virtualization-type,Values=hvm" \
        --query "sort_by(Images, &CreationDate)[-1].ImageId" \
        --output text \
        --region "$REGION")
    fi

    if [[ -z "$AMI_ID" ]]; then
      echo "[-] Error: Could not find AMI matching '$IMAGE' in region $REGION"
      echo "[!] Try specifying the exact AMI ID (ami-xxxxxxxx) instead"
      cleanup_aws
      exit 1
    fi

    echo "[+] Found matching AMI: $AMI_ID"
  fi

  # Launch instance
  INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$AWS_INSTANCE_TYPE" \
    --key-name "$AWS_KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$VM_NAME}]" \
    --query "Instances[0].InstanceId" \
    --output text)

  # Wait for instance to be running
  aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

  PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query "Reservations[0].Instances[0].PublicIpAddress" --output text)
}
################################################################################################################################
# Google Cloud
create_vm_gcp() {
  echo "[+] Provisioning GCP VM..."
  GCP_PROJECT=$(gcloud config get-value project)

  # Create firewall rule with more specific name
  FW_RULE_NAME="allow-ssh-$VM_NAME"

  if ! gcloud compute firewall-rules create "$FW_RULE_NAME" \
    --allow "tcp:$SSH_PORT" \
    --source-ranges "$SSH_CIDR" \
    --target-tags "ssh-only" \
    --description "Allow SSH to $VM_NAME"; then
    exit 1
  fi

  # Create VM
  if ! gcloud compute instances create "$VM_NAME" \
    --zone "${REGION}-a" \
    --machine-type "$GCP_MACHINE_TYPE" \
    --image-family "ubuntu-2204-lts" \
    --image-project "ubuntu-os-cloud" \
    --tags "ssh-only" \
    --metadata "ssh-keys=${ADMIN_USER}:$(cat $SSH_KEY)"; then
    cleanup_gcp
    exit 1
  fi

  PUBLIC_IP=$(gcloud compute instances describe "$VM_NAME" --zone "${REGION}-a" --format="get(networkInterfaces[0].accessConfigs[0].natIP)")
}

################################################################################################################################
### Security Hardening
################################################################################################################################
harden_vm() {
  echo "[+] Applying security hardening..."

  # Use ssh-keyscan to avoid manual host verification
  SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"

  # First test connection
  if ! ssh $SSH_OPTS -p "$SSH_PORT" "$ADMIN_USER@$PUBLIC_IP" "echo 'SSH connection test successful'"; then
    echo "[-] SSH connection failed. Cannot proceed with hardening."
    return 1
  fi

  # Apply hardening measures
  ssh $SSH_OPTS -p "$SSH_PORT" "$ADMIN_USER@$PUBLIC_IP" <<EOF
    # Update system first
    sudo apt update && sudo apt upgrade -y

    # SSH hardening
    sudo sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#\?Port .*/Port $SSH_PORT/' /etc/ssh/sshd_config

    # Restart SSH (but keep current connection alive)
    sudo systemctl reload sshd

    # Firewall (UFW) - basic setup
    sudo apt install -y ufw
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow $SSH_PORT/tcp
    echo "y" | sudo ufw enable

    # Automatic security updates
    sudo apt install -y unattended-upgrades
    sudo dpkg-reconfigure -f noninteractive unattended-upgrades

    # Install basic security tools (don't fail if any package isn't available)
    sudo apt install -y fail2ban lynis || echo "[-] Some security packages could not be installed"

    # Set up fail2ban for SSH
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    sudo sed -i "s/^port.*= ssh/port = $SSH_PORT/" /etc/fail2ban/jail.local
    sudo systemctl enable fail2ban && sudo systemctl restart fail2ban

    # Basic sysctl hardening
    echo "net.ipv4.conf.all.rp_filter=1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter=1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects=0" | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p

    # Set up basic audit logging
    sudo apt install -y auditd
    sudo systemctl enable auditd && sudo systemctl start auditd

    # Remove some unnecessary services if present
    sudo apt purge -y telnetd rsh-server rsh-redone-server || true

    # Enable automatic cleanup of unused packages
    sudo apt install -y deborphan
    echo 'APT::Periodic::AutocleanInterval "7";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades
EOF
}

################################################################################################################################
### Cloud Monitoring
################################################################################################################################
setup_cloud_monitoring() {
  case "$CLOUD" in
    azure)
      echo "[+] Enabling Azure Monitor (Insights)..."
      az extension add --name azure-monitor --yes
      az monitor log-analytics workspace create --resource-group "$RESOURCE_GROUP" --workspace-name "${VM_NAME}-logs" --output none
      az vm extension set --resource-group "$RESOURCE_GROUP" --vm-name "$VM_NAME" --name AzureMonitorLinuxAgent --publisher Microsoft.Azure.Monitor --output none
      ;;
    aws)
      echo "[+] Enabling AWS CloudWatch Agent..."
      ssh $SSH_OPTS -p "$SSH_PORT" "$ADMIN_USER@$PUBLIC_IP" <<EOF
        sudo apt update
        sudo apt install -y amazon-cloudwatch-agent
        sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c ssm:AmazonCloudWatch-linux
EOF
      ;;
    gcp)
      echo "[+] Enabling GCP Operations Suite..."
      ssh $SSH_OPTS -p "$SSH_PORT" "$ADMIN_USER@$PUBLIC_IP" <<EOF
        curl -sSO https://dl.google.com/cloudagents/add-google-cloud-ops-agent-repo.sh
        sudo bash add-google-cloud-ops-agent-repo.sh --also-install
EOF
      ;;
  esac
}

################################################################################################################################
### Package Installer
################################################################################################################################
install_packages() {
  if [[ ! -f "$PACKAGE_FILE" ]]; then
    echo "[!] No package file found at $PACKAGE_FILE, skipping package installation"
    return 0
  fi

  echo "[+] Installing packages from $PACKAGE_FILE..."
  scp $SSH_OPTS -P "$SSH_PORT" "$PACKAGE_FILE" "$ADMIN_USER@$PUBLIC_IP:/tmp/packages.txt"

  ssh $SSH_OPTS -p "$SSH_PORT" "$ADMIN_USER@$PUBLIC_IP" "
    # Update package lists
    sudo apt update

    # Check if packages file exists and has content
    if [[ ! -s /tmp/packages.txt ]]; then
      echo '[-] Package file is empty or missing'
      exit 0
    fi

    # Install packages with error handling
    while read -r pkg; do
      # Skip empty lines and comments
      [[ -z \"\$pkg\" || \"\$pkg\" =~ ^# ]] && continue

      echo \"[+] Installing \$pkg\"
      if sudo apt install -y \"\$pkg\"; then
        echo \"[+] Successfully installed \$pkg\"
      else
        echo \"[-] Failed to install \$pkg\"
      fi
    done < /tmp/packages.txt

    # Clean up
    rm -f /tmp/packages.txt
  "
}

################################################################################################################################
### SSH Waiter
################################################################################################################################
wait_for_ssh() {
  echo "[+] Waiting for SSH to be available on port $SSH_PORT..."
  local max_attempts=30
  local attempt=0
  local timeout=2

  while [[ $attempt -lt $max_attempts ]]; do
    if nc -z -w "$timeout" "$PUBLIC_IP" "$SSH_PORT" &>/dev/null; then
      echo "[+] SSH is available"
      return 0
    fi
    attempt=$((attempt + 1))
    echo "[!] Attempt $attempt/$max_attempts: SSH not ready yet, waiting..."
    sleep 5
  done

  echo "[-] SSH connection failed after $max_attempts attempts"
  return 1
}

################################################################################################################################
### Main
################################################################################################################################
main() {
  # Check for non-interactive mode
  NON_INTERACTIVE=false
  for arg in "$@"; do
    case $arg in
      --non-interactive) NON_INTERACTIVE=true; shift ;;
      --help) usage ;;
    esac
  done

  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    # Parse args for non-interactive mode
    while [[ "$#" -gt 0 ]]; do
      case $1 in
        --cloud) CLOUD="$2"; shift 2 ;;
        --name) VM_NAME="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        --user) ADMIN_USER="$2"; shift 2 ;;
        --ssh-key) SSH_KEY="$2"; shift 2 ;;
        --ssh-port) SSH_PORT="$2"; shift 2 ;;
        --ssh-cidr) SSH_CIDR="$2"; shift 2 ;;
        --packages) PACKAGE_FILE="$2"; shift 2 ;;
        --no-hardening) SECURITY_HARDENING=false; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
      esac
    done
  else
    # Interactive mode
    select_cloud_provider
    get_vm_config
  fi

  validate_inputs
  check_cli

  case "$CLOUD" in
    azure) create_vm_azure ;;
    aws) create_vm_aws ;;
    gcp) create_vm_gcp ;;
  esac

  echo "[+] VM created! Public IP: $PUBLIC_IP"

  if ! wait_for_ssh; then
    echo "[-] SSH connection failed. Cleaning up..."
    case "$CLOUD" in
      azure) cleanup_azure ;;
      aws) cleanup_aws ;;
      gcp) cleanup_gcp ;;
    esac
    exit 1
  fi

  if [[ "$SECURITY_HARDENING" == "true" ]]; then
    harden_vm || echo "[-] Security hardening encountered issues but proceeding anyway"
  fi

  if [[ -f "$PACKAGE_FILE" ]]; then
    install_packages
  else
    echo "[!] No package file found, skipping package installation"
  fi

  setup_cloud_monitoring

  echo -e "\n[+] Provisioning complete!"
  echo -e "\n\033[1;32mConnect to your VM with:\033[0m"
  echo -e "ssh -p $SSH_PORT $ADMIN_USER@$PUBLIC_IP\n"
}

################################################################################################################################
main "$@"
