#include "randomx.h"

const int WALLET_SIZE = 32;
const int VDF_SHA_HASH_SIZE = 32;

struct vdf_sha_thread_arg {
	unsigned char* walletBuffer;
	unsigned char* seed;
	unsigned char* outCheckpoint;
	int checkpointCount;
	int hashingIterations;
	unsigned char* out;
};
struct vdf_randomx_thread_arg {
	unsigned char* inputData;
	unsigned char* outCheckpoint;
	int checkpointCount;
	int hashingIterations;
	randomx_vm *vmPtr;
	unsigned char* out;
};

#if defined(__cplusplus)
extern "C" {
#endif

void vdf_sha2(unsigned char* walletInBuffer, unsigned char* seed, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations);
void vdf_randomx(unsigned char* randomxInputData, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations, randomx_vm *vmPtr);
void vdf_parallel_sha_randomx(unsigned char* walletBuffer, unsigned char* seed, unsigned char* randomxInputData, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount,
	int hashingIterationsSha, int hashingIterationsRandomx, randomx_vm *vmPtr);

#if defined(__cplusplus)
}
#endif 