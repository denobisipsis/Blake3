namespace Blake3;
/*
Zephir 0.12.20 Linux PHP extension of BLAKE3

https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

https://github.com/BLAKE3-team/BLAKE3

It supports HASH, KEYED and DERIVE modes with XOF output

This implementation have been checked with the test vectors provided

https://raw.githubusercontent.com/BLAKE3-team/BLAKE3/master/test_vectors/test_vectors.json

By default, XOF output are 32 bytes

Examples of use:

use Blake3\Blake3;

HASH MODE
		$b2 = new Blake3();		
		$hash = $b2->hash($h,$xof_length);

KEYED HASH		
						
		$b2 = new Blake3($key);		
		$keyed_hash = $b2->hash($h,$xof_length);

DERIVE KEY
		$b2 = new Blake3();		
		$derive_key = $b2->derivekey($context_key,$context,$xof_length);

@denobisipsis 2021

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files 
(the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, 
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES 
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE 
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR 
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.	   
*/	

class Blake3 
	{ 
	protected iv = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

	protected msgschedule = 
		[[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
		[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
		[3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
		[10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
		[12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
		[9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
		[11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13]];
				
	protected blocksize 		= 64;
	protected chunksize 		= 1024;	
	protected chunkstart 		= 1;
	protected chunkend 		= 2;
	protected root 		= 8;
	protected parent 		= 4;
	protected keyedhash 		= 16;
	protected derivekey 		= 32;
	protected derivekeymaterial 	= 64;			
	
	protected state;
	protected cv;
	protected key;
	protected flag;
	protected kflag;
	protected last_v;
	protected last_state;
	protected last_chunk;
	protected last_size;
	protected last_cv;
						
	public function __construct(key="") 
		{  
		var size;					
		let this->cv    = [];
		let this->state = [];
		let this->key   = "";
		let this->flag  = 0;
		let this->kflag = 0;
				
		if key
			{
			let key  = substr(key,0,this->blocksize);
			let size = strlen(key);
			
			if size<this->blocksize 
				{let key .= str_repeat(chr(0),this->blocksize-size);}
									
			let key  	   = array_values(unpack("V*",key));
			let this->cv      = key;
			let this->kflag   = this->keyedhash;					
			}
		else    {let this->cv     = this->iv;}		
		}
		
	public function derivekey(context_key="",context="",xoflength=32)
		{	
		var size,contextwords,derive_key,derive_key_words;
			
		let this->state         = this->iv;
		
		let size		 = strlen(context);	
		
		if size<this->blocksize										
			{let context   .= str_repeat(chr(0),this->blocksize-size);}
		
		let contextwords = array_values(unpack("V*",context));	
									
		let this->state  = this->chacha(this->state,contextwords,0,size,43);
			
		let this->cv 	      = array_slice(this->state,0,8);		
		let this->kflag      = this->derivekeymaterial;
			
		let derive_key       = this->hash(context_key,xoflength);		
		let derive_key_words = array_values(unpack("V*",derive_key));
					
		let this->cv 	      = derive_key_words;				
				
		return derive_key;		
		}

	public function chacha(v,chunk_words,counter,size,flag)
		{
		var sr,r,mask,shl_i1,shl_i2,shl_h1,shl_h2;
				
		let mask   = (1 << 32) - 1;	
		let shl_i1 = (1 << 16) - 1;	
		let shl_i2 = (1 << 24) - 1;	
		let shl_h1 = (1 << 20) - 1;	
		let shl_h2 = (1 << 25) - 1;	
					
		int f1,f2,f3,f4,g1,g2,g3,g4;

		let f1 = (int)v[0];
		let f2 = (int)v[1];
		let f3 = (int)v[2];
		let f4 = (int)v[3];
		let g1 = (int)v[4];
		let g2 = (int)v[5];
		let g3 = (int)v[6];
		let g4 = (int)v[7];
		
		int h1,h2,h3,h4,i1,i2,i3,i4;
						
		let h1 = 0x6a09e667;
		let h2 = 0xbb67ae85;
		let h3 = 0x3c6ef372;
		let h4 = 0xa54ff53a;
		let i1 = counter & mask;
		let i2 = (0 >> 32) & mask;
		let i3 = size;
		let i4 = flag;
							
		for r in range (0,6)
			{						
			let sr  = this->msgschedule[r];
									
			let g1  = g1 & mask;
			let g2  = g2 & mask;
			let g3  = g3 & mask;	
			let g4  = g4 & mask;

			let f1 += g1 + chunk_words[sr[0]];		
			let i1  = f1 ^ i1;									
			let i1  = (((i1 >> 16) & shl_i1)  + (i1 << 16)) & mask;   				
			let h1 += i1;							
			let g1  = g1 ^ h1;							
			let g1  = (((g1 >> 12) & shl_h1)  + (g1 << 20)) & mask; 
									
			let f1 += g1 + chunk_words[sr[1]];
			let i1  = i1 ^ f1;
			let i1  = (((i1 >> 8)  & shl_i2)  + (i1 << 24)) & mask;  
			let h1 += i1;
			let g1  = g1 ^ h1;
			let g1  = (((g1 >> 7)  & shl_h2)  + (g1 << 25)) & mask; 
			
			let f1  = f1 & mask;let h1  = h1 & mask;
			
									
			let f2 += g2 + chunk_words[sr[2]];
			let i2  = i2 ^ f2;							
			let i2  = (((i2 >> 16) & shl_i1)  + (i2 << 16)) & mask;   
			let h2 += i2;
			let g2  = g2 ^ h2;
			let g2  = (((g2 >> 12) & shl_h1)  + (g2 << 20)) & mask; 
			
			let f2 += g2 + chunk_words[sr[3]];
			let i2  = i2 ^ f2;
			let i2  = (((i2 >> 8)  & shl_i2)  + (i2 << 24)) & mask;  
			let h2 += i2;
			let g2  = g2 ^ h2;
			let g2  = (((g2 >> 7)  & shl_h2)  + (g2 << 25)) & mask;  	
			
			let f2  = f2 & mask;let h2  = h2 & mask;
													
			let f3 += g3 + chunk_words[sr[4]];
			let i3  = i3 ^ f3;							
			let i3  = (((i3 >> 16) & shl_i1)  + (i3 << 16)) & mask;   
			let h3 += i3;
			let g3  = g3 ^ h3;
			let g3  = (((g3 >> 12) & shl_h1)  + (g3 << 20)) & mask;  
			
			let f3 += g3 + chunk_words[sr[5]];
			let i3  = i3 ^ f3;
			let i3  = (((i3 >> 8)  & shl_i2)  + (i3 << 24)) & mask;   
			let h3 += i3;
			let g3  = g3 ^ h3;
			let g3  = (((g3 >> 7) & shl_h2 )  + (g3 << 25)) & mask;   
			
			let f3  = f3 & mask;let h3  = h3 & mask;
												
			let f4 += g4 + chunk_words[sr[6]];
			let i4  = i4 ^ f4;							
			let i4  = (((i4 >> 16) & shl_i1)  + (i4 << 16)) & mask;    
			let h4 += i4;
			let g4  = g4 ^ h4;
			let g4  = (((g4 >> 12) & shl_h1)  + (g4 << 20)) & mask;  
			
			let f4 += g4 + chunk_words[sr[7]];
			let i4  = i4 ^ f4;
			let i4  = (((i4 >> 8)  & shl_i2)  + (i4 << 24)) & mask;  
			let h4 += i4;
			let g4  = g4 ^ h4;
			let g4  = (((g4 >> 7)  & shl_h2)  + (g4 << 25)) & mask;   
				
			let f4  = f4 & mask;let h4  = h4 & mask;	
				
														
			let f1 += g2 + chunk_words[sr[8]];
			let i4  = i4 ^ f1;							
			let i4  = (((i4 >> 16) & shl_i1)  + (i4 << 16)) & mask;    
			let h3 += i4;
			let g2  = g2 ^ h3;
			let g2  = (((g2 >> 12) & shl_h1)  + (g2 << 20)) & mask; 
			
			let f1 += g2 + chunk_words[sr[9]];
			let i4  = i4 ^ f1;
			let i4  = (((i4 >> 8)  & shl_i2)  + (i4 << 24)) & mask;   
			let h3 += i4;
			let g2  = g2 ^ h3;
			let g2  = ((( g2 >> 7) & shl_h2)  + (g2 << 25)) & mask;   	

			let f2 += g3 + chunk_words[sr[10]];
			let i1  = i1 ^ f2;							
			let i1  = (((i1 >> 16) & shl_i1)  + (i1 << 16)) & mask;    
			let h4 += i1;
			let g3  = g3 ^ h4;
			let g3  = (((g3 >> 12) & shl_h1)  + (g3 << 20)) & mask; 
			
			let f2 += g3 + chunk_words[sr[11]];
			let i1  = i1 ^ f2;
			let i1  = (((i1 >> 8)  & shl_i2)  + (i1 << 24)) & mask;  
			let h4 += i1;
			let g3  = g3 ^ h4;
			let g3  = (((g3 >> 7)  & shl_h2)  + (g3 << 25)) & mask;   
				
			let f3 += g4 + chunk_words[sr[12]];
			let i2  = i2 ^ f3;							
			let i2  = (((i2 >> 16) & shl_i1)  + (i2 << 16)) & mask;   
			let h1 += i2;
			let g4  = g4 ^ h1;
			let g4  = (((g4 >> 12) & shl_h1)  + (g4 << 20)) & mask; 
			
			let f3 += g4 + chunk_words[sr[13]];
			let i2  = i2 ^ f3;
			let i2  = (((i2 >> 8)  & shl_i2)  + (i2 << 24)) & mask;   
			let h1 += i2;
			let g4  = g4 ^ h1;
			let g4  = (((g4 >> 7)  & shl_h2)  + (g4 << 25)) & mask;  
			
			let f4 += g1 + chunk_words[sr[14]];
			let i3  = i3 ^ f4;							
			let i3  = (((i3 >> 16) & shl_i1)  + (i3 << 16)) & mask;    
			let h2 += i3;
			let g1  = g1 ^ h2;
			let g1  = (((g1 >> 12) & shl_h1)  + (g1 << 20)) & mask;  
			
			let f4 += g1 + chunk_words[sr[15]];
			let i3  = i3 ^ f4;
			let i3  = (((i3 >> 8)  & shl_i2)  + (i3 << 24)) & mask;   
			let h2 += i3;
			let g1  = g1 ^ h2;
			let g1  = (((g1 >> 7) & shl_h2 )  + (g1 << 25)) & mask; 				
			}	        
		
		return [f1 ^ h1,f2 ^ h2,f3 ^ h3,f4 ^ h4,g1 ^ i1,g2 ^ i2,g3 ^ i3,g4 ^ i4,
		        h1 & mask,h2 & mask,h3 & mask,h4 & mask,i1 & mask,i2 & mask,i3 & mask,i4 & mask];		
		}

	public function setflags(flag = 0)
		{let this->flag = this->kflag + flag;}

	public function nodetree(tree)
		{  

		/*
		This is the reverse tree. It makes a reduction from left to right in pairs
		
		First it computes all the hashes from input data, then make the tree reduction of hashes
		till there is only one pair
		
		If there is an odd number of hashes, it pass the last hash without processing it 
		till there is a parent		
		*/
		
		this->setflags(4);
		
		var pair,chunkwords,v,chaining,flag,cv;
		
		let flag = this->flag;
		let cv   = this->cv;
		
		while count(tree)>1
			{
			let chaining = [];						
			for pair in tree
			        {						
				if count(pair) < 2 					
					{array_push(chaining,pair[0]);}					
				else    
					{		
					let chunkwords    = array_merge(pair[0],pair[1]);
					let v             = this->chacha(cv,chunkwords,0,64,flag);
					array_push(chaining,array_slice(v,0,8));
					} 
				}						
			let tree = array_chunk(chaining,2);
			}		

		let this->state = v;
		return tree;	
		}
				
	public function nodebytes(block, blockover = false)
		{ 
		var v,m,j,k,n,chunkwords,i,npad,chunks,chunk,cv,flag;
		 
		var blocksize  = 64;
		var size       = 64;
		var chunksize  = 1024;
		var hashes 	= [];  		
		let chunks 	= str_split(block,chunksize);		
		let cv     	= this->cv;
		let this->state= cv;						
		let flag   	= this->kflag;						
		let n		= count(chunks);		
								 				
		for j in range(0,n - 2)
			{			
			let chunkwords = array_chunk(array_values(unpack("V*",chunks[j])),16);
	
			let m = count(chunkwords);
								
			let v = this->chacha(cv,chunkwords[0],j,blocksize,flag+1);							
				
			for k in range (1,m - 2)
				{let v = this->chacha(v,chunkwords[k],j,blocksize,flag);}
				
			let v = this->chacha(v,chunkwords[m - 1],j,blocksize,flag+2);

			array_push(hashes,array_slice(v,0,8));
			} 
			
		let j 		= n - 1;
		let chunk 	= chunks[j];
		let m 		= strlen(chunk);
	
		if m > blocksize
			{					
			if m < chunksize 
				{								
				let size = m % blocksize;
	
				if !size 
					{let size = blocksize;}		
						        
				let npad       = ceil(m/blocksize) * blocksize;
				let chunk     .= str_repeat(chr(0),npad-m);				
				}			
						
			let chunkwords = array_chunk(array_values(unpack("V*",chunk)),16);																
			let v = this->chacha(this->state,chunkwords[0],j,blocksize,this->kflag+1);							
			for i  in range(0,7)				 
				{let v[i+8] = v[i+8] ^ this->cv[i];}
						 				 
			if blockover
				{let this->cv = array_slice(v,0,8);}
			
			let n = count(chunkwords);
								
			for k in range (1,n - 2)
				{
				let v = this->chacha(v,chunkwords[k],j,blocksize,this->kflag);

				for i in range(0,7)				 
					 {let v[i+8] = v[i+8] ^ this->cv[i];}	 
					 				 
				if blockover
					 {let this->cv = array_slice(v,0,8);}				
				}
				
			let this->state = v;
											
			if blockover 
				 {
				 this->setflags(10); 
				 let j = 0;
				 }
			else     {this->setflags(2);}
			
			let chunkwords = chunkwords[n - 1];
			}
		  else
			{
			let size = m;
			
			let chunkwords = array_values(unpack("V*",chunk.str_repeat(chr(0),blocksize-size)));
						
			let flag = 3;			
							
			if blockover
				{
				let flag   += 8;
				let j       = 0;
				}				
					
			this->setflags(flag);	
			}
					
		// for XOF output
			
		let this->last_cv	= this->cv;
		let this->last_state	= this->state;			
										
		let v = this->chacha(this->state,chunkwords,j,size,this->flag);	
									
		for i in range(0,7)				 
			{let v[i+8] = v[i+8] ^ $this->cv[i];}	
					 				 
		if blockover
			{let this->cv = array_slice(v,0,8);}			 				 
		
		array_push(hashes,array_slice(v,0,8));
												
		// last_v for generating the first xof digest
		
		let this->last_chunk 	= chunkwords;
		let this->last_size 	= size;								
		let this->last_v 	= v;	
					
		return hashes;			
		}
		
	public function XOFoutput(hash, XOFdigestlength)
		{
		// Output bytes. By default 32

		var cycles, XofHash, last_bytes, i, k, v;
		
		let cycles 	= floor(XOFdigestlength/this->blocksize);			
		let XofHash	= hash;			

		for i in range(8,15)
			{let XofHash .= pack("V*",this->last_v[i]);} 				
				
		for k in range(1,cycles)
			{			
			let v = this->chacha(this->last_state,this->last_chunk,k,this->last_size,this->flag);

			for i in range(0,7)				 
				 {let v[i+8] = v[i+8] ^ this->last_cv[i];}
			
			for i in range(0,15)
				{let XofHash .= pack("V*",v[i]);} 			
			}
  		
		// final xof bytes 
		
		let last_bytes = this->blocksize-(XOFdigestlength % this->blocksize);
		
		if last_bytes!=this->blocksize 		 
			{let XofHash = substr(XofHash,0,-last_bytes);}		

		return bin2hex(XofHash);		
		}		
	
	public function hash(block, XOFdigestlength = 32)
		{
		var blockover, tree, chunkwords, v, i, hash;
		
		if strlen(block) <= this->chunksize 
			 {let blockover = true;}
		else    {let blockover = false;}
		
		let tree = array_chunk(this->nodebytes(block, blockover),2);
		
		if count(tree) > 1 						
			{let tree = this->nodetree(tree);}
								
		if count(tree[0]) > 1
			{
			let this->state    = this->cv;			
								
			let chunkwords     = array_merge(tree[0][0],tree[0][1]);

			let this->last_cv 	= this->cv;
			let this->last_state 	= this->cv;
			let this->last_chunk 	= chunkwords;
			let this->last_size 	= 64;
				
			this->setflags(this->chunkstart + this->chunkend + this->root + 1);
				
			let v = this->chacha(this->state,chunkwords,0,64,this->flag);

			for i in range(0,7)				 
				 {let v[i+8] = v[i+8] ^ this->cv[i];}
							 				 				
			let this->last_v = v;			
			
			for i in range(0,7)
				{let hash   .= pack("V*",v[i]);} 				
			}			
		else 	{
			for i in range(0,7)
				{let hash   .= pack("V*",tree[0][0][i]);} 
			}
					
		return this->XOFoutput(hash,XOFdigestlength);
		}
	}

