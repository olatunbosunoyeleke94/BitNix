savedcmd_/bitnix/kernel/bitnix.mod := printf '%s\n'   bitnix.o | awk '!x[$$0]++ { print("/bitnix/kernel/"$$0) }' > /bitnix/kernel/bitnix.mod
