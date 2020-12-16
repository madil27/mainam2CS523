sudo auditctl -a exit,never -F uid=0
sudo auditctl -a exit,never -F exe=/usr/sbin/sshd
sudo auditctl -a exit,never -F exe=/usr/bin/bash
sudo auditctl -a exit,always -F arch=b64 -F success=1 -S execve,link,open,close,read,readv,write,writev,unlink,unlinkat
sudo auditctl -a exit,always -F arch=b32 -F success=1 -S execve,link,open,close,read,readv,write,writev,unlink,unlinkat
sudo auditctl -a exit,always -F arch=b64 -S exit,exit_group
sudo auditctl -a exit,always -F arch=b32 -S exit,exit_group