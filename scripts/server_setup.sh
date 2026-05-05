#!/bin/bash
# Run this ONCE on your Oracle server to set up the repo sync structure
# Usage: bash server_setup.sh YOUR_GITHUB_REPO_URL
# Example: bash server_setup.sh https://github.com/yourname/tfii.git

set -e

REPO_URL=$1
if [ -z "$REPO_URL" ]; then
  echo "Usage: bash server_setup.sh https://github.com/yourname/tfii.git"
  exit 1
fi

echo "=== TFII Server Setup ==="

# 1. Clone the repo to a sync directory
if [ ! -d "/home/ubuntu/threatfeed-repo" ]; then
  git clone "$REPO_URL" /home/ubuntu/threatfeed-repo
  echo "✓ Repo cloned to /home/ubuntu/threatfeed-repo"
else
  echo "~ Repo already exists at /home/ubuntu/threatfeed-repo"
fi

# 2. Create deploy key for GitHub Actions SSH access
if [ ! -f "/home/ubuntu/.ssh/github_deploy" ]; then
  ssh-keygen -t ed25519 -f /home/ubuntu/.ssh/github_deploy -N "" -C "tfii-deploy"
  echo ""
  echo "=== ADD THIS DEPLOY/SSH KEY TO GITHUB ACTIONS SECRETS ==="
  echo "Secret name: SERVER_SSH_KEY"
  echo "Secret value (copy everything below):"
  echo "---"
  cat /home/ubuntu/.ssh/github_deploy
  echo "---"
  echo ""
  cat /home/ubuntu/.ssh/github_deploy.pub >> /home/ubuntu/.ssh/authorized_keys
  chmod 600 /home/ubuntu/.ssh/authorized_keys
  echo "✓ Deploy key created and added to authorized_keys"
else
  echo "~ Deploy key already exists"
  echo "Public key (already authorized):"
  cat /home/ubuntu/.ssh/github_deploy.pub
fi

# 3. Sudo permission for systemctl restart (no password)
SUDOERS_LINE="ubuntu ALL=(ALL) NOPASSWD: /bin/systemctl restart threatfeed, /bin/systemctl is-active threatfeed, /bin/journalctl -u threatfeed *"
if ! sudo grep -q "threatfeed" /etc/sudoers 2>/dev/null; then
  echo "$SUDOERS_LINE" | sudo tee -a /etc/sudoers.d/tfii-deploy > /dev/null
  echo "✓ Sudoers rule added (systemctl restart without password)"
else
  echo "~ Sudoers rule already exists"
fi

echo ""
echo "=== GitHub Actions Secrets to add ==="
echo "Go to: https://github.com/YOUR_REPO/settings/secrets/actions"
echo ""
echo "SERVER_HOST    = $(curl -s ifconfig.me 2>/dev/null || echo 'YOUR_SERVER_IP')"
echo "SERVER_USER    = ubuntu"
echo "SERVER_SSH_KEY = (the private key printed above)"
echo ""
echo "=== Setup complete ==="
