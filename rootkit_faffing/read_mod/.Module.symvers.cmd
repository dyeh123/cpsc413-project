cmd_/home/alvin/Desktop/rootkit_faffing/read_mod/Module.symvers := sed 's/ko$$/o/' /home/alvin/Desktop/rootkit_faffing/read_mod/modules.order | scripts/mod/modpost -m -a   -o /home/alvin/Desktop/rootkit_faffing/read_mod/Module.symvers -e -i Module.symvers   -T -
