#!/usr/bin/env bash
################################################################################################################################
### hal-provisoner v2: a Multi-Cloud VM Provisioner (Azure/AWS/GCP)
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
### Config
CLOUD="azure"
VM_NAME="devbox01"
REGION="eastus"
ADMIN_USER="adminuser"
SSH_KEY="$HOME/.ssh/id_rsa.pub"
IMAGE="Ubuntu2204"
SIZE="Standard_B1s"  # Azure
AWS_INSTANCE_TYPE="t3.small"  # AWS
GCP_MACHINE_TYPE="e2-small"  # GCP
RESOURCE_GROUP="provision-rg"
PACKAGE_FILE="packages.txt"
TAGS="Environment=Dev,Owner=Admin"
SECURITY_HARDENING=true
SSH_PORT=22  # Default SSH port
SSH_CIDR="$(curl -s --fail --connect-timeout 3 ifconfig.me || echo "0.0.0.0")/32"  # Current IP with fallback
################################################################################################################################
### Usage // Help
usage() {
  echo "Usage: $0 --cloud <azure|aws|gcp> [options]"
  echo "Options:"
  echo "  --cloud <provider>    Cloud provider (azure/aws/gcp)"
  echo "  --name <vm-name>      VM name (default: devbox01)"
  echo "  --region <region>     Region (default: eastus/us-east-1)"
  echo "  --user <username>     Admin username (default: adminuser)"
  echo "  --ssh-key <path>      SSH public key path (default: ~/.ssh/id_rsa.pub)"
  echo "  --ssh-port <port>     Custom SSH port (default: 22)"
  echo "  --ssh-cidr <cidr>     Allowed SSH CIDR (default: your public IP)"
  echo "  --packages <file>     Package list file (default: packages.txt)"
  echo "  --no-hardening       Skip security hardening"
  echo "  --help               Show this help"
  exit 0
}
################################################################################################################################
### Validation
validate_inputs() {
  # Validate cloud provider
  case "$CLOUD" in
    azure|aws|gcp) ;;
    *) echo "[-] Invalid cloud provider. Use: azure, aws, gcp"; exit 1 ;;
  esac

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
# Azure VM Provisioning
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

# AWS VM Provisioning
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

  # Get Ubuntu 22.04 AMI
  AMI_ID=$(aws ssm get-parameter --name /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id --query "Parameter.Value" --output text)

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

# GCP VM Provisioning
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
### Wait for SSH to be available
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
  # Parse args
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
      --help) usage ;;
      *) echo "Unknown argument: $1"; exit 1 ;;
    esac
  done

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
