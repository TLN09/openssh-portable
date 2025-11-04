#!/bin/sh
timestamp="`/Users/tln/cs/masters/openssh-portable/regress/timestamp`"
logfile="/Users/tln/cs/masters/openssh-portable/regress/log/${timestamp}.ssh.$$.log"
echo "Executing: /Users/tln/cs/masters/openssh-portable/ssh $@" log ${logfile} >>/Users/tln/cs/masters/openssh-portable/regress/regress.log
echo "Executing: /Users/tln/cs/masters/openssh-portable/ssh $@" >>${logfile}
for i in "$@";do shift;case "$i" in -q):;; *) set -- "$@" "$i";;esac;done
rm -f /Users/tln/cs/masters/openssh-portable/regress/ssh.log
ln -f -s ${logfile} /Users/tln/cs/masters/openssh-portable/regress/ssh.log
exec /Users/tln/cs/masters/openssh-portable/ssh -E${logfile} "$@"
