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

pki_name=$(whiptail --inputbox "What would you like to name your new PKI?" 9 48 Smallstep --title "Config Step CA" 3>&1 1>&2 2>&3)
if [ ! $? ]; then
    echo "User selected Cancel."
    exit 1
fi

pki_dns=$(whiptail --inputbox "What DNS names or IP addresses will clients use to reach your CA?" 9 48 ca.example.com --title "Config Step CA" 3>&1 1>&2 2>&3)
if [ ! $? ]; then
    echo "User selected Cancel."
    exit 1
fi

pki_provisioner=$(whiptail --inputbox "What would you like to name the CA's first provisioner?" 9 48 you@smallstep.com --title "Config Step CA" 3>&1 1>&2 2>&3)
if [ ! $? ]; then
    echo "User selected Cancel."
    exit 1
fi

msg_info "Config Step CA"
export STEPPATH="/opt/step-ca"
mkdir -p $STEPPATH
#mkdir -p /opt/step-ca

useradd --user-group --system --home /opt/step-ca --shell /bin/false step

# generate random password for CA and subCA
openssl rand -base64 99 | tr -dc 'a-zA-Z0-9' | head -c33 >/opt/step-ca/CApassword.txt
openssl rand -base64 99 | tr -dc 'a-zA-Z0-9' | head -c33 >/opt/step-ca/password.txt

$STD step ca init --deployment-type=standalone --name=$pki_name --dns=$pki_dns --address=:443 --provisioner=$pki_provisioner --password-file=/opt/step-ca/CApassword.txt --acme
#$STD step ca init --deployment-type=standalone --name=Smallstep --dns=ca.example.com --address=:443 --provisioner=you@smallstep.com --password-file=/opt/step-ca/CApassword.txt --acme
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
  echo "Step CA Private key password:" `cat /opt/step-ca/CApassword.txt`
  echo "  SubCA Private key password:" `cat /opt/step-ca/password.txt`
  echo "Fingerprint of CA:" `step certificate fingerprint /opt/step-ca/certs/root_ca.crt`
  echo "Root certificates are available at https://$pki_dns/roots.pem"
  step certificate inspect /opt/step-ca/certs/root_ca.crt --short
  cat /opt/step-ca/certs/root_ca.crt
  echo "ACME directory server URL: https://$pki_dns/acme/ACME/directory"
  echo "https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/"
} >>~/stepca.creds

#################
# verander geldigheidsduur CA = 30 year subCA = 1 year + auto rotate subCA
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
#$STD systemctl status step-ca
msg_ok "Configured Service"

# ${YW} ${BOLD} ${RD} ${GN}
PROFILE_FILE="/etc/profile.d/10_stepca-details.sh"
temp_file=`mktemp`
{
  echo "${YW}The public key of the root CA can be found at ${GN}/opt/step-ca/certs/root_ca.crt${CL}"
  echo "${YW}or at ${BGN}https://$pki_dns/roots.pem${CL}"
  echo "${YW}Fingerprint of CA ${GN}"`step certificate fingerprint /opt/step-ca/certs/root_ca.crt`"${CL}"
#  step certificate inspect /opt/step-ca/certs/root_ca.crt --short
#  cat /opt/step-ca/certs/root_ca.crt
  echo -e "${CL}"
  echo "${YW}The ACME directory server URL is ${BGN}https://$pki_dns/acme/ACME/directory${CL}"
  echo "${YW}Documentation on how to connect an ACME client to this server can be found at${CL}"
  echo "${BGN}https://smallstep.com/docs/tutorials/acme-protocol-acme-clients/${CL}"
  echo "${CL}"
} >$temp_file
echo -e "${CL}"
cat $temp_file | while read -r line; do
  echo -e " $line"
done
cat $temp_file | while read -r line; do
  echo "echo -e \" $line\""
done > $PROFILE_FILE

motd_ssh
customize

msg_info "Cleaning up"
rm -f "$temp_file"
$STD apt-get -y autoremove
$STD apt-get -y autoclean
msg_ok "Cleaned"
