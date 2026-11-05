set pagination off
set disable-randomization on
break *0x4019cb
run
printf "STATE:"
x/16xb $rsp+0x130
printf "END\n"
kill
quit
