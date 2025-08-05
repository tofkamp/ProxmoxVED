#!/usr/bin/env bash

# Copyright (c) 2021-2025 community-scripts ORG
# Author: Tjibbe Hofkamp (tofkamp)
# License: MIT | https://github.com/community-scripts/ProxmoxVE/raw/main/LICENSE
# Source: https://snipeitapp.com/

source /dev/stdin <<<"$FUNCTIONS_FILE_PATH"
color
verb_ip6
catch_errors
setting_up_container
network_check
update_os

msg_info "Installing Dependencies"
$STD apt-get install -y \
  setcap 
msg_ok "Installed Dependencies"

msg_info "Installing Step CA"
apt-get update && apt-get install -y --no-install-recommends curl vim gpg ca-certificates
curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/smallstep.asc
echo 'deb [signed-by=/usr/share/keyrings/smallstep.asc] https://packages.smallstep.com/stable/debian debs main' | sudo tee /etc/apt/sources.list.d/smallstep.list  >/dev/null
$STD apt-get update
$STD apt-get -y install step-cli step-ca
msg_ok "Installed Step CA"


msg_info "Config Step CA"
useradd --user-group --system --home /opt/step-ca --shell /bin/false step

CA_PASS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9' | head -c23)
SUBCA_PASS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9' | head -c23)
#echo $CA_PASS >/opt/step-ca/CApassword.txt
echo "$SUBCA_PASS" >/opt/step-ca/password.txt
# iets van step ca init
{
  echo "Step CA-Credentials"
  echo "Step CA Password: $CA_PASS"
  echo "Step CA SubCA Password: $SUBCA_PASS"
  echo "Fingerprint of CA: $CA_FINGERPRINT"
} >>~/setpca.creds
msg_ok "Configed Step CA"

chown -R step:step /opt/step-ca
chmod -R 700 /opt/step-ca

msg_info "Creating Service"
cat <<EOF >/etc/systemd/system/step-ca.service
[Unit]
Description=step-ca service
Documentation=https://smallstep.com/docs/step-ca
Documentation=https://smallstep.com/docs/step-ca/certificate-authority-server-production
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=3
ConditionFileNotEmpty=/opt/step-ca/config/ca.json
ConditionFileNotEmpty=/opt/step-ca/password.txt

[Service]
Type=simple
User=step
Group=step
Environment=STEPPATH=/opt/step-ca
WorkingDirectory=/opt/step-ca
ExecStart=/usr/bin/step-ca config/ca.json --password-file password.txt
ExecReload=/bin/kill --signal HUP $MAINPID
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=30
StartLimitBurst=3

; Process capabilities & privileges
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
SecureBits=keep-caps
NoNewPrivileges=yes

; Sandboxing
ProtectSystem=full
ProtectHome=true
RestrictNamespaces=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
PrivateTmp=true
PrivateDevices=true
ProtectClock=true
ProtectControlGroups=true
ProtectKernelTunables=true
ProtectKernelLogs=true
ProtectKernelModules=true
LockPersonality=true
RestrictSUIDSGID=true
RemoveIPC=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
ReadWriteDirectories=/opt/step-ca/db

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable -q --now step-ca
msg_ok "Configured Service"

motd_ssh
customize

msg_info "Cleaning up"
#rm -f "$temp_file"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"
