#include <miner.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "rfv2/rfv2.h"

//Pointer for allocation of ByteCollusion Memory Space
uint32_t *ByteCollusionSpace = NULL;

int scanhash_rfv2(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t _ALIGN(64) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	volatile uint8_t *restart = &(work_restart[thr_id].restart);
	void *rambox;
	int ret = 0;

	if (opt_benchmark)
		Htarg = ptarget[7] = 0x1ffffff;

	//printf("thd%d work=%p htarg=%08x ptarg7=%08x first_nonce=%08x max_nonce=%08x hashes_done=%Lu\n",
	//       thr_id, work, Htarg, ptarget[7], first_nonce, max_nonce, (unsigned long)*hashes_done);

	for (int k=0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);
	
	// EXTRACT HOW MANY BYTES FOR COLLUSION FROM THE nBITS FILED VALUE
	// Subtract from 0x20(32) the actual Diff aka 0x1f/0x1d = to get how mayn bytes to check for collusion
	int32_t nBytesCollusion = 0x1f - (endiandata[18] >> 24);
	printf("\nnByteCollusion = %02x\n", nBytesCollusion);
	if(nBytesCollusion < 3)
		nBytesCollusion = 3;

	if(ByteCollusionSpace == NULL) {
		// INIT BYTE COLLUSION SPACE USING
		// FIRST 32 BITS OF THE FRACTIONAl PARTS OF THE SQUARE ROOTS OF THE FIRST 1024 PRIMES 3..8167

		ByteCollusionSpace = calloc(1024, sizeof(uint32_t));
		if(ByteCollusionSpace == NULL)
			goto out;
		
		int32_t i = 3, nPrime, c;
		uint32_t PrimeSQRootFraction = 0;

		for(nPrime=0; nPrime<1024; ) {
			for(c=2; c<=i-1; c++) {
				if(i%c == 0)
					break;
			}
			
			if(c==i) {
				PrimeSQRootFraction = (uint32_t)(fmod(sqrt(i), 1.0) * pow(2.0, 32.0));
				//printf("%04d: %04d | %08x\n", nPrime, i, PrimeSQRootFraction);
				memcpy(ByteCollusionSpace+nPrime, &PrimeSQRootFraction, sizeof(unsigned int));
				nPrime++;
			}
			
			i++;
		}
	}
	
	//CHECK THE ByteCollisionSpace
	//for(unsigned int x=0; x<1024; x++) {
	//	printf("%04d: %p | %08x\n", x, ByteCollusionSpace+x, *(ByteCollusionSpace+x));
	//}
	
	uint32_t nBytePos;
	
	//Loop Maximal 1024 concanated uint32 fraction of primes a4 Bytes minus the ByteCollusion part
	uint32_t nMaxBytesLookup = 1024 * sizeof(uint32_t) - nBytesCollusion;

	rambox = malloc(RFV2_RAMBOX_SIZE * 8);
	if (rambox == NULL)
		goto out;

	rfv2_raminit(rambox);
	// pre-compute the hash state based on the constant part of the header

	do {
		be32enc(&endiandata[19], nonce);
		rfv2_hash(hash, endiandata, 80, rambox, NULL);

		// SCAN TROUGH 4096 BYTES OF MEMORY TO CHECK FOR A BYTE COLLUSION WITH nBYTES FROM THE HASH
		for(nBytePos=0; nBytePos<nMaxBytesLookup; nBytePos++) {
			//CHECK BYTE FOR BYTE IF A nBYTE COLLUSION EXIST IN THE MEM SPACE
			// IF YES SUBMIT SHARE / BLOCK TO NETWORK AS SOLUTION WAS FOUND

			if( !memcmp(&((char *)ByteCollusionSpace)[nBytePos], hash, nBytesCollusion) ) {
				printf("BINGOOOO BLOCK NONCE FOUND SUBMITING TO NETWORK !!!!  NONCE = %08x\n", nonce);
				applog_hex((void *) hash, 32); 
				work_set_target_ratio(work, hash);
				pdata[19] = nonce;
				*hashes_done = pdata[19] - first_nonce;
				ret = 1;
				goto out;
			}
		}
	next:
		nonce++;
	} while (nonce < max_nonce && !(*restart));

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
out:
	free(rambox);
	return ret;
}
