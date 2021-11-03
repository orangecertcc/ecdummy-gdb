set pagination off
set logging off
b main
r
# breakpoint at ecp_nistz256_point_add_affine
b *0xb6e94540 
# breakpoint somewhere in ecp_nistz256_mul_mont
b *0xb6e935a0
disable 2
disable 3
kill

set $ctr=0
while($ctr<2000)
  print $ctr
  r privkey_secp256r1.pem message.txt sig_safeerror_wbooth.bin
  # do nothing in first 35 points additions
  enable 2
  ignore 2 35
  c
  # now we are at the last point addition
  # the target is the 5th mult in point addition
  # (arbitrary choice)
  enable 3
  ignore 3 4
  c
  # modify a register with a "random" value
  set $r3=0x55adab
  disable 2
  disable 3
  c
  set $ctr=$ctr+1
end
quit
