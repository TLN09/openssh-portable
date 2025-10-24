#!/bin/sh
timestamp="`/Users/tln/cs/masters/openssh-portable/regress/timestamp`"
logfile="/Users/tln/cs/masters/openssh-portable/regress/log/${timestamp}.sshd.$$.log"
rm -f /Users/tln/cs/masters/openssh-portable/regress/sshd.log
touch $logfile
test -z "" || chown tln $logfile
ln -f -s ${logfile} /Users/tln/cs/masters/openssh-portable/regress/sshd.log
echo "Executing: /Users/tln/cs/masters/openssh-portable/sshd $@" log ${logfile} >>/Users/tln/cs/masters/openssh-portable/regress/regress.log
echo "Executing: /Users/tln/cs/masters/openssh-portable/sshd $@" >>${logfile}
exec /Users/tln/cs/masters/openssh-portable/sshd -E${logfile} "$@"
