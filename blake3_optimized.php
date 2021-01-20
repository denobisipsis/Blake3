<?
/*
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
*/

ini_set('precision', 8);	
	
class BLAKE3 
	{ 
	const IV = [
	0x6a09e667, 0xbb67ae85,
	0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19
	];
		
	const BLOCK_SIZE 	= 64;
	const HEX_BLOCK_SIZE	= 128;
	const CHUNK_SIZE 	= 1024;
	const KEY_SIZE 		= 32;
	const HASH_SIZE 	= 32;
	const PARENT_SIZE 	= 2 * 32;
	const WORD_BITS 	= 32;
	const WORD_BYTES 	= 4;
	const WORD_MAX 		= 2**32 - 1;
	const HEADER_SIZE 	= 8;
	
	# domain flags
	const CHUNK_START 		= 1 << 0;
	const CHUNK_END 		= 1 << 1;
	const ROOT 			= 1 << 3;
	const PARENT 			= 1 << 2;
	const KEYED_HASH 		= 1 << 4;
	const DERIVE_KEY 		= 1 << 5;
	const DERIVE_KEY_MATERIAL 	= 1 << 6;
			
	const PACKING = "V*";
				
	function __construct($key="")
		{  					
		$this->cv    = [];
		$this->state = [];
		$this->key   = "";
		$this->flag			= 0;
		$this->kflag			= 0;
		
		if ($key)
			{
			$key  = substr($key,0,self::BLOCK_SIZE);
			$size = strlen($key);
			
			if ($size<self::BLOCK_SIZE)
			$key .= str_repeat("\x0",self::BLOCK_SIZE-strlen($key));
									
			$key  = array_values(unpack(self::PACKING,$key));
			$this->cv      = $key;
			$this->kflag   = self::KEYED_HASH;					
			}
		else    $this->cv      = self::IV;		
		}
		
	function derivekey($context_key="",$context="",$xof_length)
		{		
		$this->state     = self::IV;
		
		$size		 = strlen($context);	
		if ($size<self::BLOCK_SIZE)										
			$context.= str_repeat("\0",self::BLOCK_SIZE-$size);

		$context_words = array_values(unpack(self::PACKING,$context));								
		self::chacha($context_words,0,$size,43);
			
		$this->cv = array_slice($this->state,0,8);		
		$this->kflag      = self::DERIVE_KEY_MATERIAL;
				
		$derive_key       = self::hash($context_key,$xof_length);		
		$derive_key_words = array_values(unpack(self::PACKING,$derive_key));
					
		$this->cv 	  = $derive_key_words;				
				
		return $derive_key;		
		}

	function chacha($chunk_words,$counter,$size,$flag,$is_xof=false,$block_over=false)
		{
		$MSG_SCHEDULE = [
		[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
		[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
		[3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
		[10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
		[12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
		[9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
		[11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
		];
		
		$v = $this->state;
		
		$mask   = self::WORD_MAX;
	
		$shl_i1 = (1 << 16) - 1;
		$shl_i2 = (1 << 24) - 1;
		$shl_h1 = (1 << 20) - 1;
		$shl_h2 = (1 << 25) - 1;		
		
		$f1 = $v[0];
		$f2 = $v[1];
		$f3 = $v[2];
		$f4 = $v[3];
		$g1 = $v[4];
		$g2 = $v[5];
		$g3 = $v[6];
		$g4 = $v[7];
		$h1 = 0x6a09e667;
		$h2 = 0xbb67ae85;
		$h3 = 0x3c6ef372;
		$h4 = 0xa54ff53a;
		$i1 = $counter & $mask;
		$i2 = ($counter >> 32) & $mask;
		$i3 = $size;
		$i4 = $flag;
							
		for ($r=0;$r<7;$r++)
			{
			$sr = $MSG_SCHEDULE[$r];			
			
			$f1 += $g1 + $chunk_words[$sr[0]];
			$i1 ^= $f1;							
			$i1  = ((($i1 >> 16) & $shl_i1)  | ($i1 << 16)) & $mask;   
			$h1 += $i1 ;
			$g1 ^= $h1;
			$g1  = ((($g1 >> 12) & $shl_h1)  | ($g1 << 20)) & $mask; 
			
			$f1 += $g1 + $chunk_words[$sr[1]];
			$i1 ^= $f1;
			$i1  = ((($i1 >> 8)  & $shl_i2)  | ($i1 << 24)) & $mask;  
			$h1 += $i1;
			$g1 ^= $h1;
			$g1  = (( $g1 >> 7)  & $shl_h2)  | ($g1 << 25);  
	
			$f1 &= $mask;$g1 &= $mask;$h1 &= $mask;
						
			$f2 += $g2 + $chunk_words[$sr[2]];
			$i2 ^= $f2;							
			$i2  = ((($i2 >> 16) & $shl_i1)  | ($i2 << 16)) & $mask;   
			$h2 += $i2;
			$g2 ^= $h2;
			$g2  = ((($g2 >> 12) & $shl_h1)  | ($g2 << 20)) & $mask; 
			
			$f2 += $g2 + $chunk_words[$sr[3]];
			$i2 ^= $f2;
			$i2  = ((($i2 >> 8)  & $shl_i2)  | ($i2 << 24)) & $mask;  
			$h2 += $i2;
			$g2 ^= $h2;
			$g2  = (( $g2 >> 7)  & $shl_h2)  | ($g2 << 25);  
	
			$f2 &= $mask;$g2 &= $mask;$h2 &= $mask;		
											
			$f3 += $g3 + $chunk_words[$sr[4]];
			$i3 ^= $f3;							
			$i3  = ((($i3 >> 16) & $shl_i1)  | ($i3 << 16)) & $mask;   
			$h3 += $i3;
			$g3 ^= $h3;
			$g3  = ((($g3 >> 12) & $shl_h1)  | ($g3 << 20)) & $mask; 
			
			$f3 += $g3 + $chunk_words[$sr[5]];
			$i3 ^= $f3;
			$i3  = ((($i3 >> 8)  & $shl_i2)  | ($i3 << 24)) & $mask;  
			$h3 += $i3;
			$g3 ^= $h3;
			$g3  = (( $g3 >> 7)  & $shl_h2)  | ($g3 << 25);  
	
			$f3 &= $mask;$g3 &= $mask;$h3 &= $mask;
									
			$f4 += $g4 + $chunk_words[$sr[6]];
			$i4 ^= $f4;							
			$i4  = ((($i4 >> 16) & $shl_i1)  | ($i4 << 16)) & $mask;   
			$h4 += $i4;
			$g4 ^= $h4;
			$g4  = ((($g4 >> 12) & $shl_h1)  | ($g4 << 20)) & $mask; 
			
			$f4 += $g4 + $chunk_words[$sr[7]];
			$i4 ^= $f4;
			$i4  = ((($i4 >> 8)  & $shl_i2)  | ($i4 << 24)) & $mask;  
			$h4 += $i4;
			$g4 ^= $h4;
			$g4  = (( $g4 >> 7)  & $shl_h2)  | ($g4 << 25);  
	
			$f4 &= $mask;$g4 &= $mask;$h4 &= $mask;
									
			$f1 += $g2 + $chunk_words[$sr[8]];
			$i4 ^= $f1;							
			$i4  = ((($i4 >> 16) & $shl_i1)  | ($i4 << 16)) & $mask;   
			$h3 += $i4;
			$g2 ^= $h3;
			$g2  = ((($g2 >> 12) & $shl_h1)  | ($g2 << 20)) & $mask; 
			
			$f1 += $g2 + $chunk_words[$sr[9]];
			$i4 ^= $f1;
			$i4  = ((($i4 >> 8)  & $shl_i2)  | ($i4 << 24)) & $mask;  
			$h3 += $i4;
			$g2 ^= $h3;
			$g2  = (( $g2 >> 7)  & $shl_h2)  | ($g2 << 25);  	

			$f2 += $g3 + $chunk_words[$sr[10]];
			$i1 ^= $f2;							
			$i1  = ((($i1 >> 16) & $shl_i1)  | ($i1 << 16)) & $mask;   
			$h4 += $i1;
			$g3 ^= $h4;
			$g3  = ((($g3 >> 12) & $shl_h1)  | ($g3 << 20)) & $mask; 
			
			$f2 += $g3 + $chunk_words[$sr[11]];
			$i1 ^= $f2;
			$i1  = ((($i1 >> 8)  & $shl_i2)  | ($i1 << 24)) & $mask;  
			$h4 += $i1;
			$g3 ^= $h4;
			$g3  = (( $g3 >> 7)  & $shl_h2)  | ($g3 << 25);  
	
			$f3 += $g4 + $chunk_words[$sr[12]];
			$i2 ^= $f3;							
			$i2  = ((($i2 >> 16) & $shl_i1)  | ($i2 << 16)) & $mask;   
			$h1 += $i2;
			$g4 ^= $h1;
			$g4  = ((($g4 >> 12) & $shl_h1)  | ($g4 << 20)) & $mask; 
			
			$f3 += $g4 + $chunk_words[$sr[13]];
			$i2 ^= $f3;
			$i2  = ((($i2 >> 8)  & $shl_i2)  | ($i2 << 24)) & $mask;  
			$h1 += $i2;
			$g4 ^= $h1;
			$g4  = (( $g4 >> 7)  & $shl_h2)  | ($g4 << 25);  
	
			$f4 += $g1 + $chunk_words[$sr[14]];
			$i3 ^= $f4;							
			$i3  = ((($i3 >> 16) & $shl_i1)  | ($i3 << 16)) & $mask;   
			$h2 += $i3;
			$g1 ^= $h2;
			$g1  = ((($g1 >> 12) & $shl_h1)  | ($g1 << 20)) & $mask; 
			
			$f4 += $g1 + $chunk_words[$sr[15]];
			$i3 ^= $f4;
			$i3  = ((($i3 >> 8)  & $shl_i2)  | ($i3 << 24)) & $mask;  
			$h2 += $i3;
			$g1 ^= $h2;
			$g1  = (( $g1 >> 7)  & $shl_h2)  | ($g1 << 25);  									
			}
			
		$v[0] = $f1 ^ $h1;
		$v[1] = $f2 ^ $h2;
		$v[2] = $f3 ^ $h3;
		$v[3] = $f4 ^ $h4;
		$v[4] = $g1 ^ $i1;
		$v[5] = $g2 ^ $i2;
		$v[6] = $g3 ^ $i3;
		$v[7] = $g4 ^ $i4;
		$v[8] = $h1 & $mask;
		$v[9] = $h2 & $mask;
		$v[10]= $h3 & $mask;
		$v[11]= $h4 & $mask;
		$v[12]= $i1 & $mask;
		$v[13]= $i2 & $mask;
		$v[14]= $i3 & $mask;
		$v[15]= $i4 & $mask;
						 			
		if ($is_xof)
			{			
			for ($i=0;$i<8;$i++)				 
				 $v[$i+8] ^= $this->cv[$i];			 				 
			if (!$block_over)
				$this->cv  = array_slice($v,0,8);	
			}
			
		$this->state = $v;				
		}

	function setflags($start = 0)
		{
		$this->flag = $this->kflag + $start;					
		}

	function nodetree($tree)
		{  
		self::setflags(4);
				
		while (sizeof($tree)>1)
			{
			$chaining = "";			
			foreach ($tree as $pair)
			        {						
				if (strlen($pair) < 64) 					
					$chaining.= $pair;					
				else    
					{							 					
					$this->state     = $this->cv;			
					$chunk_words     = array_values(unpack("V*",$pair));
										
					self::chacha($chunk_words,0,64,$this->flag);						
								
					$chaining .= pack("V*",...array_slice($this->state,0,8));
					} 
				}						
			$tree = str_split($chaining,64);
			}

		return $tree;	
		}
				
	function nodebytes($block, $is_root = false)
		{  
		$BLOCK_SIZE     = self::BLOCK_SIZE;
		$CHUNK_SIZE     = self::CHUNK_SIZE;
		$hashes 	= "";  		
		$chunks 	= str_split($block,$CHUNK_SIZE);		
		$size    	= $BLOCK_SIZE;
					 				
		for ($j=0;$j<sizeof($chunks)-1;$j++)
			{	
			$this->state = $this->cv;	
			
			$chunk_words = array_chunk(array_values(unpack("V*",$chunks[$j])),16);							
			self::chacha($chunk_words[0],$j,$BLOCK_SIZE,$this->kflag+1, true, !$is_root);				
			for ($k=1;$k<sizeof($chunk_words)-1;$k++)
				self::chacha($chunk_words[$k],$j,$BLOCK_SIZE,$this->kflag, true, !$is_root);
			self::chacha($chunk_words[$k],$j,$size,$this->kflag+2, true, !$is_root);
											
			$hashes .= pack("V*",...array_slice($this->state,0,8));			
			} 

		$this->state = $this->cv;	
		
		if (strlen($chunks[$j]) > $BLOCK_SIZE)
			{			
			if (strlen($chunks[$j]) < $CHUNK_SIZE) 
				{									
				$size = strlen($chunks[$j]) % $BLOCK_SIZE;
	
				if (!$size) 
					$size = $BLOCK_SIZE;		
						        
				$npad	      = ceil(strlen($chunks[$j])/$BLOCK_SIZE) * $BLOCK_SIZE;
				$chunks[$j]  .= str_repeat("\x0",$npad-strlen($chunks[$j]));
				}			
						
			$chunk_words = array_chunk(array_values(unpack("V*",$chunks[$j])),16);			
										
			self::chacha($chunk_words[0],$j,$BLOCK_SIZE,$this->kflag+1, true, !$is_root);				

			for ($k=1;$k<sizeof($chunk_words)-1;$k++)
				self::chacha($chunk_words[$k],$j,$BLOCK_SIZE,$this->kflag, true, !$is_root);
											
			if ($is_root) 
				 {
				 self::setflags(10); 
				 $j = 0;
				 }
			else     self::setflags(2);
			
			$chunk_words = $chunk_words[$k];
			}
		else
			{
			$size = strlen($chunks[$j]);
			$chunk_words = array_values(unpack("V*",$chunks[$j].str_repeat("\x0",$BLOCK_SIZE-strlen($chunks[$j]))));
							
			$flag = 3;			
							
			if ($is_root)
				{
				$flag   |= 8;
				$j 	 = 0;
				}				
					
			self::setflags($flag);	
			}
					
		// for XOF output
									
		$this->last_cv	 	= $this->cv;
		$this->last_state	= $this->state;
			
		self::chacha($chunk_words,$j,$size,$this->flag, true, !$is_root);
										
		$hashes .= pack("V*",...array_slice($this->state,0,8));
																	
		// last_v for generating the first xof digest
		
		$this->last_chunk 	= $chunk_words;
		$this->last_size 	= $size;								
		$this->last_v 		= $this->state;	
		
		return $hashes;			
		}
		
	function XOF_output($hash, $XOF_digest_length)
		{
		// Output bytes. By default 32

		$cycles 	= ceil($XOF_digest_length/self::BLOCK_SIZE);			
		$XofHash	= $hash;			
		$XofHash       .= pack(self::PACKING,...array_slice($this->last_v,8));
		
		for ($k=1;$k<$cycles;$k++)
			{
			$this->cv 	= $this->last_cv;		
			$this->state	= $this->last_state;
			self::chacha($this->last_chunk,$k,$this->last_size,$this->flag,true);				 
			$XofHash       .= pack(self::PACKING,...$this->state); 			
			}
  		
		// final xof bytes 
		
		$last_bytes = self::BLOCK_SIZE-($XOF_digest_length % self::BLOCK_SIZE);
		
		if ($last_bytes!=self::BLOCK_SIZE) 		 
			$XofHash = substr($XofHash,0,-$last_bytes);		
		
		return bin2hex($XofHash);		
		}		
	
	function hash($block, $XOF_digest_length = 32)
		{
		if (strlen($block) <= self::CHUNK_SIZE) 
			$is_root = true;
		else    $is_root = false;
		
		$tree = str_split(self::nodebytes($block, $is_root),self::BLOCK_SIZE);	
		/*
		This is the reverse tree. It makes a reduction from left to right in pairs
		
		First it computes all the hashes from input data, then make the tree reduction of hashes
		till there is only one pair
		
		If there is an odd number of hashes, it pass the last hash without processing it 
		till there is a parent		
		*/
		if (sizeof($tree)>1) 						
			$tree = self::nodetree($tree);
						
		if (strlen($tree[0]) > 32)
			{			
			$this->state     = $this->cv;
						
			$chunk_words     = array_values(unpack("V*",$tree[0]));

			$this->last_cv	 	= $this->cv;
			$this->last_state 	= $this->state;
			$this->last_chunk 	= $chunk_words;
			$this->last_size 	= 64;
			
			$flag    = self::CHUNK_START | self::CHUNK_END | self::ROOT;	
			self::setflags(++$flag);
						
			self::chacha($chunk_words,0,64,$this->flag,1);						
			
			$this->last_v = $this->state;
			
			$hash = pack("V*",...array_slice($this->state,0,8));
			}			
		else 	$hash = $tree[0];
					
		return self::XOF_output($hash,$XOF_digest_length);
		}
	}
	
function test_blake3()
	{	
	// official
	
	$xof_length = 131;
	
	$vectors = file_get_contents("http://raw.githubusercontent.com/BLAKE3-team/BLAKE3/master/test_vectors/test_vectors.json");
	$vectors = array_slice(explode('"input_len"',$vectors),1);
	foreach ($vectors as $vector)
		{		
		$len    	= trim(explode(',',explode(':',$vector)[1])[0]);		
		$rhash 		= trim(explode('"',explode('hash":',$vector)[1])[1]);
		$rkeyed_hash 	= trim(explode('"',explode('"keyed_hash": "',$vector)[1])[0]);
		$rderive_key 	= trim(explode('"',explode('"derive_key": "',$vector)[1])[0]);
		
		echo $len." ";
		
		$h="";
		for ($g=0;$g<$len;$g++) 			
			$h.=pack("c",$g % 251);

		$b2 = new BLAKE3();		
		$hash = $b2->hash($h,$xof_length);
		
		echo "hash ";
		if ($hash != $rhash) die("bad hash \n $hash \n $rhash");
						
		$b2 = new BLAKE3("whats the Elvish word for friend");		
		$keyed_hash = $b2->hash($h,$xof_length);

		echo "keyed_hash ";
		if ($keyed_hash != $rkeyed_hash) die("bad keyed_hash \n $keyed_hash \n $rkeyed_hash");	

		$b2 = new BLAKE3();		
		$derive_key = $b2->derivekey($h,"BLAKE3 2019-12-27 16:29:52 test vectors context",$xof_length);
		
		echo "derive_key ";
		if ($derive_key != $rderive_key) die("bad derive_key");
		
		echo " Ok\n";
		}
	echo "test_blake3 Ok\n";
	}
	
function big_test($count=10000000)
	{
	/*
	Bytes generated like generate_vectors.py, from https://github.com/oconnor663/bao/tree/master/tests
	
	Check this performance against the python script https://github.com/oconnor663/bao/blob/master/tests/test_bao.py
	
	with 
	
	import datetime

	a = datetime.datetime.now()	
	input_bytes = generate_input.input_bytes(1000000)		
	computed_hash = bao_hash(input_bytes)
	b = datetime.datetime.now()
	delta = b - a
	print(delta)
	print(computed_hash)	
	*/
	ini_set('precision', 8);
	
	$exp      = floor(log($count, 1024)) | 0;
    	$unit     = array('B', 'KB', 'MB', 'GB', 'TB');   
    	$size     = round($count / (pow(1024, $exp)), 2).$unit[$exp];
	
	echo "Big_test of $size\n";
	
	$b = "";
	$i = 1;
	while ($count > 0)
		{
		$ibytes = pack("V*",$i);
		$take   = min(4, $count);
		$b     .= substr($ibytes,0,$take); 
		$count -= $take;
		$i     += 1;
		}
	$t = microtime(true);		
	$b2 = new BLAKE3();		
	$hash = $b2->hash($b);
	echo $hash."\n";
	echo round(microtime(true)-$t,8)." s\n";	
	}

test_blake3();	
big_test();
