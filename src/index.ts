var buf = Buffer.alloc(8);
var tmp = 8;
for (let i = 0; i < 8; i++) {
    console.log(buf,'before put')
  // mask 0xff over number to get last 8
  buf[7 - i] = tmp & 0xff;

  console.log(buf.toString(),'after put')


  // shift 8 and get ready to loop over the next batch of 8
  tmp = tmp >> 8;

  console.log(tmp,'after shift')

}
