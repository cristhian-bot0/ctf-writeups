set pagination off
set disable-randomization on
break *0x401664
run
printf "KS:"
x/48xb $rsp+0x150
kill
quit
