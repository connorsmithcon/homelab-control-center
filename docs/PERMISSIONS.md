# Ports and permissions

## Network ports

| Direction | Default | Purpose | Required |
| --- | ---: | --- | --- |
| Browser to control host | TCP 8088 | Dashboard and API | Yes |
| Control host to remote nodes | TCP 22 | Agentless SSH monitoring | Only for remote nodes |
| Control host to GitHub | TCP 443 | Install and update downloads | During install or update |

The application does not open a firewall rule automatically.

## Local operating-system identities

| Identity | Privilege | Purpose |
| --- | --- | --- |
| hcc | Unprivileged system user | Web service, database, and SSH collector |
| root action broker | Root service with group-restricted socket | Fixed local systemctl and apt-get actions |
| installer | Root, interactive operation | Creates identities, files, and systemd units |

The web service is not a member of docker, libvirt, or other root-equivalent groups.

## Filesystem permissions

| Path | Owner and mode |
| --- | --- |
| /etc/homelab-control-center | root:hcc 0750 |
| config.json | root:hcc 0640 |
| /var/lib/homelab-control-center | hcc:hcc 0750 |
| control-center.db | hcc:hcc 0600 through process umask |
| .ssh | hcc:hcc 0700 |
| SSH private key | hcc:hcc 0600 |
| bootstrap-token | root:hcc 0640, deleted after setup |
| action socket | root:hcc 0660 |
| installed releases | root:root, not writable by hcc |

## Remote read-only account

Create a dedicated unprivileged account on each Linux node. It needs:

- SSH public-key login
- read access to /proc
- permission to run systemctl list-units
- membership in systemd-journal only if journal viewing is wanted

It does not need the docker group. Membership in docker is effectively root access and is intentionally not requested.

## Optional remote actions

Version 0.1.0 ships extras/install-node-helper.sh. Run it directly on a remote node after inspecting it:

~~~bash
curl -fsSLO https://raw.githubusercontent.com/connorsmithcon/homelab-control-center/main/extras/install-node-helper.sh
less install-node-helper.sh
sudo bash install-node-helper.sh hccmon
~~~

The helper installs a root-owned validator and a sudoers rule that permits only that validator. The remote user cannot send arbitrary shell commands through the control center.
