set pagination off
set disable-randomization on
break *0x4018c6
break *0x401993
break *0x4019b9
run
printf "AFTER_B:"
x/16xb $rsp+0x130
continue
printf "AFTER_C:"
x/16xb $rsp+0x130
continue
printf "AFTER_D:"
x/16xb $rsp+0x130
kill
quit
