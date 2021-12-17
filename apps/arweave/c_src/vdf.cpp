#include <thread>
#include <cstring>
#include <openssl/sha.h>
#include "randomx_long_with_entropy.h"
#include "vdf.h"

void _vdf_sha2(unsigned char* walletBuffer, unsigned char* seed, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations) {
	unsigned char tempOut[VDF_SHA_HASH_SIZE];
	for(int checkpointIdx = 0; checkpointIdx <= checkpointCount; checkpointIdx++) {
		unsigned char* locIn  = checkpointIdx == 0               ? seed : (outCheckpoint + VDF_SHA_HASH_SIZE*(checkpointIdx-1));
		unsigned char* locOut = checkpointIdx == checkpointCount ? out  : (outCheckpoint + VDF_SHA_HASH_SIZE*checkpointIdx);
		{
			SHA256_CTX sha256;
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, walletBuffer, WALLET_SIZE);
			SHA256_Update(&sha256, locIn, VDF_SHA_HASH_SIZE); // -1 memcpy
			SHA256_Final(tempOut, &sha256);
		}
		for(int i = 1; i < hashingIterations; i++) {
			SHA256_CTX sha256;
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, walletBuffer, WALLET_SIZE);
			SHA256_Update(&sha256, tempOut, VDF_SHA_HASH_SIZE);
			SHA256_Final(tempOut, &sha256);
		}
		{
			SHA256_CTX sha256;
			SHA256_Init(&sha256);
			SHA256_Update(&sha256, walletBuffer, WALLET_SIZE);
			SHA256_Update(&sha256, tempOut, VDF_SHA_HASH_SIZE);
			SHA256_Final(locOut, &sha256);
		}
	}
}

// use
//   unsigned char out[VDF_SHA_HASH_SIZE];
//   unsigned char* outCheckpoint = (unsigned char*)malloc(checkpointCount*VDF_SHA_HASH_SIZE);
//   free(outCheckpoint);
// for call
void vdf_sha2(unsigned char* walletInBuffer, unsigned char* seed, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations) {
	unsigned char walletBuffer[WALLET_SIZE];
	// ensure 1 L1 cache page used
	// no access to heap, except of 0-iteration
	memcpy(walletBuffer, walletInBuffer, WALLET_SIZE);

	_vdf_sha2(walletBuffer, seed, out, outCheckpoint, checkpointCount, hashingIterations);
}

void vdf_randomx(unsigned char* randomxInputData, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations, randomx_vm *vmPtr) {
	for(int checkpointIdx = 0; checkpointIdx <= checkpointCount; checkpointIdx++) {
		size_t locInSize      = checkpointIdx == 0               ? RANDOMX_HASH_SIZE + WALLET_SIZE : RANDOMX_HASH_SIZE;
		unsigned char* locIn  = checkpointIdx == 0               ? randomxInputData : (outCheckpoint + RANDOMX_HASH_SIZE*(checkpointIdx-1));
		unsigned char* locOut = checkpointIdx == checkpointCount ? out              : (outCheckpoint + RANDOMX_HASH_SIZE*checkpointIdx);
		randomx_calculate_hash_long(vmPtr, locIn, locInSize, locOut, hashingIterations);
	}
}


void _vdf_sha_thread(struct vdf_sha_thread_arg* arg) {
	_vdf_sha2(arg->walletBuffer, arg->seed, arg->out, arg->outCheckpoint, arg->checkpointCount, arg->hashingIterations);
}
void _vdf_randomx_thread(struct vdf_randomx_thread_arg* arg) {
	vdf_randomx(arg->inputData, arg->out, arg->outCheckpoint, arg->checkpointCount, arg->hashingIterations, arg->vmPtr);
}

// layout of outCheckpoint = all sha256 checkpoints | all randomx checkpoints
void vdf_parallel_sha_randomx(unsigned char* walletInBuffer, unsigned char* seed, unsigned char* randomxInputData, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount,
	int hashingIterationsSha, int hashingIterationsRandomx, randomx_vm *vmPtr) {
	// sequential reference impl
	// unsigned char sha_temp_result[VDF_SHA_HASH_SIZE];
	// vdf_sha2(walletBuffer, seed, sha_temp_result, hashingIterationsSha);
	// unsigned char randomx_temp_result[RANDOMX_HASH_SIZE];
	// randomx_calculate_hash_long(vmPtr, inputData, WALLET_SIZE+VDF_SHA_HASH_SIZE, randomx_temp_result, hashingIterationsRandomx);
	// {
		// SHA256_CTX sha256;
		// SHA256_Init(&sha256);
		// SHA256_Update(&sha256, sha_temp_result, VDF_SHA_HASH_SIZE);
		// SHA256_Update(&sha256, randomx_temp_result, RANDOMX_HASH_SIZE);
		// SHA256_Final(out, &sha256);
	// }

	unsigned char sha_temp_result[VDF_SHA_HASH_SIZE];
	unsigned char randomx_temp_result[RANDOMX_HASH_SIZE];
	unsigned char walletBuffer[WALLET_SIZE];
	// ensure 1 L1 cache page used
	// no access to heap, except of 0-iteration
	memcpy(walletBuffer, walletInBuffer, WALLET_SIZE);

	struct vdf_sha_thread_arg _vdf_sha_thread_arg;
	struct vdf_randomx_thread_arg _vdf_randomx_thread_arg;

	_vdf_sha_thread_arg.walletBuffer = walletBuffer;
	_vdf_sha_thread_arg.seed = seed;
	_vdf_sha_thread_arg.outCheckpoint = outCheckpoint;
	_vdf_sha_thread_arg.checkpointCount = checkpointCount;
	_vdf_sha_thread_arg.hashingIterations = hashingIterationsSha;
	_vdf_sha_thread_arg.out = sha_temp_result;

	_vdf_randomx_thread_arg.inputData = randomxInputData;
	_vdf_randomx_thread_arg.vmPtr = vmPtr;
	_vdf_randomx_thread_arg.outCheckpoint = outCheckpoint + checkpointCount*VDF_SHA_HASH_SIZE;
	_vdf_randomx_thread_arg.checkpointCount = checkpointCount;
	_vdf_randomx_thread_arg.hashingIterations = hashingIterationsRandomx;
	_vdf_randomx_thread_arg.out = randomx_temp_result;

	std::thread sha_thread(_vdf_sha_thread, &_vdf_sha_thread_arg);
	std::thread randomx_thread(_vdf_randomx_thread, &_vdf_randomx_thread_arg);

	sha_thread.join();
	randomx_thread.join();
	{
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, sha_temp_result, VDF_SHA_HASH_SIZE);
		SHA256_Update(&sha256, randomx_temp_result, RANDOMX_HASH_SIZE);
		SHA256_Final(out, &sha256);
	}
}

// TODO fast verification, thread limit
