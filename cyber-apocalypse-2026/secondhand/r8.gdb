set pagination off
set disable-randomization on
break *0x401df5
run
printf "r8=0x%lx rax_at_first_imul=0x%lx\n", $r8, $rax
kill
quit
