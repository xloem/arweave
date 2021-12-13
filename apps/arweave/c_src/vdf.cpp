#include <thread>
#include <cstring>
#include <openssl/sha.h>
#include "randomx_long_with_entropy.h"
#include "vdf.h"

void _vdf_sha2(unsigned char* walletBuffer, unsigned char* seed, unsigned char* out, int hashingIterations) {
	{
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, walletBuffer, WALLET_SIZE);
		SHA256_Update(&sha256, seed, VDF_SHA_HASH_SIZE); // -1 memcpy
		SHA256_Final(out, &sha256);
	}
	for(int i = 0; i < hashingIterations; i++) {
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, walletBuffer, WALLET_SIZE);
		SHA256_Update(&sha256, out, VDF_SHA_HASH_SIZE);
		SHA256_Final(out, &sha256);
	}
}

// use
//   unsigned char out[VDF_SHA_HASH_SIZE];
// for call
void vdf_sha2(unsigned char* walletInBuffer, unsigned char* seed, unsigned char* out, int hashingIterations) {
	unsigned char walletBuffer[WALLET_SIZE];
	// ensure 1 L1 cache page used
	// no access to heap, except of 0-iteration
	memcpy(walletBuffer, walletInBuffer, WALLET_SIZE);

	_vdf_sha2(walletBuffer, seed, out, hashingIterations);
}


void _vdf_sha_thread(struct vdf_sha_thread_arg* arg) {
	_vdf_sha2(arg->walletBuffer, arg->seed, arg->res, arg->hashingIterations);
}
void _vdf_randomx_thread(struct vdf_randomx_thread_arg* arg) {
	randomx_calculate_hash_long(arg->vmPtr, arg->inputData, WALLET_SIZE+VDF_SHA_HASH_SIZE, arg->res, arg->hashingIterations);
}

void vdf_parallel_sha_randomx(unsigned char* walletBuffer, unsigned char* seed, unsigned char* randomxInputData, unsigned char* out, int hashingIterationsSha, int hashingIterationsRandomx, randomx_vm *vmPtr) {
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

	struct vdf_sha_thread_arg _vdf_sha_thread_arg;
	struct vdf_randomx_thread_arg _vdf_randomx_thread_arg;

	_vdf_sha_thread_arg.walletBuffer = walletBuffer;
	_vdf_sha_thread_arg.seed = seed;
	_vdf_sha_thread_arg.hashingIterations = hashingIterationsSha;
	_vdf_sha_thread_arg.res = sha_temp_result;

	_vdf_randomx_thread_arg.inputData = randomxInputData;
	_vdf_randomx_thread_arg.vmPtr = vmPtr;
	_vdf_randomx_thread_arg.hashingIterations = hashingIterationsRandomx;
	_vdf_randomx_thread_arg.res = randomx_temp_result;

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
