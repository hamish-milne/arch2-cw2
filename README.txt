Cache simulator (Computer architecture Coursework 2)
====================================================

The simulator should work as specified. I've added in a few extra
features to deal with malformed inputs:
   - Default values for the command-line input
   - Fatal errors for too many address bits (maximum 32) and when
     out of memory
   - Warning for when the input data is unaligned (not exactly
     one word long)
   - Error when a request contains too few arguments
   - Warning when a request contains too many arguments
   - Message when the address is near the end of a block,
     which causes effectively two operations to be performed

For clarification, I'll also list the access times for various
operations and situations, in terms of HIT, READ and WRITE
   - Read hit: HIT
   - Read miss: HIT + READ
   - Read miss, end of block: HIT + READ + READ
   - Write hit: HIT
   - Write miss: HIT + READ
   - Write miss, one block: HIT
   - Write miss, end of block: HIT + READ + READ
   - Cache eviction: WRITE (added to any 'miss' operation)
   - Flush: HIT * cache_blocks + WRITE * dirty_blocks
