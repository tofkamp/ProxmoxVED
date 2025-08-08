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

#msg_info "Installing Dependencies"
#$STD apt-get install -y \
#  libcap2-bin 
#msg_ok "Installed Dependencies"

msg_info "Installing Step CA"
$STD apt-get update
$STD apt-get install -y --no-install-recommends curl ca-certificates
curl -fsSL https://packages.smallstep.com/keys/apt/repo-signing-key.gpg -o /etc/apt/trusted.gpg.d/smallstep.asc
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/smallstep.asc] https://packages.smallstep.com/stable/debian debs main' | sudo tee /etc/apt/sources.list.d/smallstep.list  >/dev/null
$STD apt-get update
$STD apt-get -y install step-cli step-ca
msg_ok "Installed Step CA"

################# https://en.wikibooks.org/wiki/Bash_Shell_Scripting/Whiptail
# vraag FQDN of server
# vraag email address
# vraag enable auto-update
# vervang step-ca door $APP

msg_info "Config Step CA"
export STEPPATH="/opt/setp-ca"
mkdir -p /opt/setp-ca
useradd --user-group --system --home /opt/setp-ca --shell /bin/false step

openssl rand -base64 99 | tr -dc 'a-zA-Z0-9' | head -c33 >/opt/step-ca/CApassword.txt
openssl rand -base64 99 | tr -dc 'a-zA-Z0-9' | head -c33 >/opt/step-ca/password.txt

$STD step ca init --deployment-type=standalone --name=Smallstep --dns=ca.example.com --address=:443 --provisioner=you@smallstep.com --password-file=/opt/step-ca/CApassword.txt --acme
# change password of subCA
$STD step crypto change-pass $(step path)/secrets/intermediate_ca_key --password-file=/opt/step-ca/CApassword.txt --new-password-file=/opt/step-ca/password.txt --force
chown -R step:step /opt/step-ca
chmod -R og-rwx /opt/step-ca
# insert in ../config/ca.json
cat << EOF | sed -i '/"name": "acme"/ r /dev/stdin' /opt/step-ca/config/ca.json
                                "claims": {
                                        "enableSSHCA": false,
                                        "disableRenewal": false,
                                        "allowRenewalAfterExpiry": false,
                                        "disableSmallstepExtensions": false,
                                        "minTLSCertDuration": "24h",
                                        "maxTLSCertDuration:": "1100h",
                                        "defaultTLSCertDuration": "720h"
                                }
EOF
step-ca version >/opt/step-ca_version.txt

{
  echo "Step CA-Credentials"
  echo "Step CA Password:" `cat /opt/step-ca/CApassword.txt`
  echo "Step CA SubCA Password:" `cat /opt/step-ca/password.txt`
  echo "Fingerprint of CA:" `step certificate fingerprint /opt/step-ca/certs/root_ca.crt`
  echo "Root certificates are available at https://ca.example.com:443/roots.pem"
  cat /opt/step-ca/certs/root_ca.crt
  echo "ACME server URL: https://ca.example.com:443/acme/acme/directory"
  echo "ga naar http://... voor een voorbeeld"
} >>~/stepca.creds

#################
# motd heeft geen kronkeltje voor root
# verander geldigheidsduur
# verander domeinen
# version textfile
# upgrade via apt ?

msg_ok "Configed Step CA"

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
ExecReload=/bin/kill --signal HUP \$MAINPID
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
$STD systemctl status step-ca
msg_ok "Configured Service"

motd_ssh
customize

msg_info "Cleaning up"
#rm -f "$temp_file"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"
set
