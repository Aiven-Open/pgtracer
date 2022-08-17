#!/bin/bash
set -e

# Create a directory for the container
mkdir ~/fedora
mkdir -p /var/lib/machines/fedora
mount -o bind ~/fedora /var/lib/machines/fedora
mkdir -p /etc/distro.repos.d
# Configure yum repos for fedora
cat << EOF > /etc/distro.repos.d/fedora.repo
[fedora]
name=Fedora  \$releasever – \$basearch
failovermethod=priority
baseurl=http://download.fedoraproject.org/pub/fedora/linux/releases/\$releasever/Everything/\$basearch/os
metalink=https://mirrors.fedoraproject.org/metalink?repo=fedora-\$releasever&arch=\$basearch
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-\$releasever-\$basearch
metadata_expire=2d
skip_if_unavailable=False
EOF

# Install the fedora key for f36
# TODO: generalize it
mkdir -p /etc/pki/rpm-gpg/
wget https://getfedora.org/static/fedora.gpg -O /etc/pki/rpm-gpg/RPM-GPG-KEY-fedora-36-x86_64

# Install the required packages in the container
dnf -y --releasever=36 --best \
  --setopt=install_weak_deps=False \
  --installroot=/var/lib/machines/fedora/ \
  install \
  dhcp-client dnf fedora-release glibc glibc-langpack-en glibc-langpack-de \
  iputils less ncurses passwd systemd \
  systemd-networkd systemd-resolved util-linux vim-default-editor \
  postgresql-server dnf-utils dnf-plugins-core \
  python-bcc python-pip

rm /var/lib/machines/fedora/etc/resolv.conf
cp /etc/resolv.conf /var/lib/machines/fedora/etc/resolve.conf


systemd-nspawn -D /var/lib/machines/fedora/ /usr/bin/dnf -y --releasever=36 debuginfo-install postgresql-server

#systemd-nspawn -D /var/lib/machines/fedora/ /usr/bin/pip install toml setuptools
#cp -r ./ /var/lib/machines/fedora/root/pgtracer/
#systemd-nspawn -D /var/lib/machines/fedora/ /usr/bin/pip install -r /root/pgtracer/requirements.txt.tmp

# Set a dummy password for the root user
systemd-nspawn --console=pipe -D /var/lib/machines/fedora/ passwd root --stdin << EOF
fedora
EOF

systemctl start systemd-nspawn@fedora
sleep 2
systemd-run --machine fedora --pipe --wait  /usr/bin/postgresql-setup --initdb
systemd-run --machine fedora --pipe --wait /usr/bin/sed "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /var/lib/pgsql/data/postgresql.conf -i
systemd-run --machine fedora --pipe --wait /usr/bin/bash -c 'echo "host all all 0.0.0.0/0 trust" > /var/lib/pgsql/data/pg_hba.conf'
systemd-run --machine fedora --pipe --wait /usr/bin/systemctl enable postgresql --now


systemd-run --machine fedora --pipe --wait /usr/sbin/ip link set up host0
systemd-run --machine fedora --pipe --wait /usr/sbin/ip addr add 172.16.0.1/30 dev host0
systemd-run --machine fedora --pipe --wait /usr/sbin/ip route add default dev host0

# Ok, now we need to assign a static IP address
ip link   set up ve-fedora
ip route add 172.16.0.0/30 dev ve-fedora
ip addr add 172.16.0.2/30 dev ve-fedora
