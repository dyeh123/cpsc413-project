cmd_/home/alvin/Desktop/rootkit_faffing/modules.order := {   echo /home/alvin/Desktop/rootkit_faffing/example.ko; :; } | awk '!x[$$0]++' - > /home/alvin/Desktop/rootkit_faffing/modules.order
