#include "randomx.h"

const int WALLET_SIZE = 32;
const int VDF_SHA_HASH_SIZE = 32;

struct vdf_sha_thread_arg {
	unsigned char* walletBuffer;
	unsigned char* seed;
	int hashingIterations;
	unsigned char* res;
};
struct vdf_randomx_thread_arg {
	unsigned char* inputData;
	int hashingIterations;
	randomx_vm *vmPtr;
	unsigned char* res;
};

#if defined(__cplusplus)
extern "C" {
#endif

void vdf_sha2(unsigned char* walletInBuffer, unsigned char* seed, unsigned char* out, int hashingIterations);
void vdf_parallel_sha_randomx(unsigned char* walletBuffer, unsigned char* seed, unsigned char* randomxInputData, unsigned char* out, int hashingIterationsSha, int hashingIterationsRandomx, randomx_vm *vmPtr);

#if defined(__cplusplus)
}
#endif 