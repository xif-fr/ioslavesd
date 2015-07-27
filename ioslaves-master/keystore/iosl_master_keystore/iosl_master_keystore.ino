/**
 *  Example with Atmel 24C64AN = 8192 bytes
 *  Can store a 512B index and 30x 256B keys
 *
 *  0x0000 / 
 *    |    | { [slave_id \0][keynum_uint8] } x ... 
 *   512B  |
 *    |    \_ 
 *  0x0200 /
 *         \_  keynum=0 256B key
 *  0x0300 /
 *         \_  keynum=1 256B key
 *  0x0400 /
 *         \_  keynum=2 256B key
 *  0x0500 /
 *  .      .
 *  .      .
 *  .      \_
 *  0x1800 /
 *         \_  keynum=28 256B key
 *  0x1900 /
 *  0x1999 \_  keynum=39 256B key
 *
 */