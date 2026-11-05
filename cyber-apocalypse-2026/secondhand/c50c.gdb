set pagination off
set disable-randomization on
break *0x401a81
break *0x401a92
run
printf "C50=0x%lx\n", $rax
continue
printf "D90=0x%lx\n", $rax
kill
quit
