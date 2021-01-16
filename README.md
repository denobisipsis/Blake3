# Blake3
PHP Blake3 hash,keyed_hash,derive_key,XOF
PHP implementation of BLAKE3

https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

https://github.com/BLAKE3-team/BLAKE3

It supports HASH, KEYED and DERIVE modes with XOF output

There is a python version https://github.com/oconnor663/bao

which is 2.5x slower than this implementation in generating the hash

This implementation have been checked with the test vectors provided

https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/master/test_vectors/test_vectors.json

By default, XOF output are 32 bytes

Examples of use:

HASH MODE
		$b2 = new BLAKE3();		
		$hash = $b2->hash($h,$xof_length);

KEYED HASH		
						
		$b2 = new BLAKE3($key);		
		$keyed_hash = $b2->hash($h,$xof_length);

DERIVE KEY
		$b2 = new BLAKE3();		
		$derive_key = $b2->derivekey($context_key,$context,$xof_length);
		

@denobisipsis 2021
