#include <thread>
#include <cstring>
#include <vector>
#include <mutex>
#include <openssl/sha.h>
#include <gmp.h>
#include "randomx_long_with_entropy.h"
#include "vdf.h"

struct vdf_sha_thread_arg {
	unsigned char* walletBuffer;
	unsigned char* seed;
	unsigned char* outCheckpoint;
	int checkpointCount;
	int hashingIterations;
	unsigned char* out;
};
struct vdf_randomx_thread_arg {
	unsigned char* walletBuffer;
	unsigned char* seed;
	unsigned char* outCheckpoint;
	int checkpointCount;
	int hashingIterations;
	randomx_vm *vmPtr;
	unsigned char* out;
};

struct vdf_sha_verify_thread_arg;
struct vdf_randomx_verify_thread_arg;

class vdf_verify_job {
public:
	unsigned char* walletBuffer;
	unsigned char* seed;
	unsigned char* inCheckpointSha;
	unsigned char* inCheckpointRandomx;
	int checkpointCount;
	int hashingIterationsSha;
	int hashingIterationsRandomx;
	randomx_flags flags;

	std::vector<vdf_sha_verify_thread_arg    > _vdf_sha_verify_thread_arg_list;
	std::vector<vdf_randomx_verify_thread_arg> _vdf_randomx_verify_thread_arg_list;
	volatile bool verifyRes;
	std::mutex lock;
};

struct vdf_sha_verify_thread_arg {
	std::thread* thread;
	volatile bool in_progress;

	vdf_verify_job* job;
	int checkpointIdx;
};

struct vdf_randomx_verify_thread_arg {
	std::thread* thread;
	volatile bool in_progress;

	vdf_verify_job* job;
	int checkpointIdx;
	randomx_vm *vmPtr;
};

////////////////////////////////////////////////////////////////////////////////////////////////////
//    SHA
////////////////////////////////////////////////////////////////////////////////////////////////////

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
		for(int i = 2; i < hashingIterations; i++) {
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
void vdf_sha2(unsigned char* walletBuffer, unsigned char* seed, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations) {
	unsigned char walletBufferStack[WALLET_SIZE];
	// ensure 1 L1 cache page used
	// no access to heap, except of 0-iteration
	memcpy(walletBufferStack, walletBuffer, WALLET_SIZE);

	_vdf_sha2(walletBufferStack, seed, out, outCheckpoint, checkpointCount, hashingIterations);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    Randomx
////////////////////////////////////////////////////////////////////////////////////////////////////

void vdf_randomx(unsigned char* walletBuffer, unsigned char* seed, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount, int hashingIterations, randomx_vm *vmPtr) {
	unsigned char tempBuf[WALLET_SIZE + RANDOMX_HASH_SIZE];
	memcpy(tempBuf, walletBuffer, WALLET_SIZE);
	memcpy(tempBuf+WALLET_SIZE, seed, RANDOMX_HASH_SIZE);

	for(int checkpointIdx = 0; checkpointIdx <= checkpointCount; checkpointIdx++) {
		unsigned char* locOut = checkpointIdx == checkpointCount ? out              : (outCheckpoint + RANDOMX_HASH_SIZE*checkpointIdx);
		randomx_calculate_hash_long(vmPtr, tempBuf, WALLET_SIZE + RANDOMX_HASH_SIZE, locOut, hashingIterations);
		if (checkpointIdx != checkpointCount) {
			memcpy(tempBuf + WALLET_SIZE, locOut, RANDOMX_HASH_SIZE);
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    SHA+Randomx
////////////////////////////////////////////////////////////////////////////////////////////////////

void _vdf_sha_thread(struct vdf_sha_thread_arg* arg) {
	_vdf_sha2(arg->walletBuffer, arg->seed, arg->out, arg->outCheckpoint, arg->checkpointCount, arg->hashingIterations);
	unsigned char* lastCheckpoint = arg->outCheckpoint + arg->checkpointCount*VDF_SHA_HASH_SIZE;
	memcpy(lastCheckpoint, arg->out, VDF_SHA_HASH_SIZE);
}
void _vdf_randomx_thread(struct vdf_randomx_thread_arg* arg) {
	vdf_randomx(arg->walletBuffer, arg->seed, arg->out, arg->outCheckpoint, arg->checkpointCount, arg->hashingIterations, arg->vmPtr);
	unsigned char* lastCheckpoint = arg->outCheckpoint + arg->checkpointCount*RANDOMX_HASH_SIZE;
	memcpy(lastCheckpoint, arg->out, RANDOMX_HASH_SIZE);
}

// layout of outCheckpoint = all sha256 checkpoints | all randomx checkpoints
void vdf_parallel_sha_randomx(unsigned char* walletBuffer, unsigned char* seed, unsigned char* out, unsigned char* outCheckpoint, int checkpointCount,
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
	unsigned char walletBufferStack[WALLET_SIZE];
	// ensure 1 L1 cache page used
	// no access to heap, except of 0-iteration
	memcpy(walletBufferStack, walletBuffer, WALLET_SIZE);

	struct vdf_sha_thread_arg _vdf_sha_thread_arg;
	struct vdf_randomx_thread_arg _vdf_randomx_thread_arg;

	_vdf_sha_thread_arg.walletBuffer = walletBufferStack;
	_vdf_sha_thread_arg.seed = seed;
	_vdf_sha_thread_arg.outCheckpoint = outCheckpoint;
	_vdf_sha_thread_arg.checkpointCount = checkpointCount;
	_vdf_sha_thread_arg.hashingIterations = hashingIterationsSha;
	_vdf_sha_thread_arg.out = sha_temp_result;

	_vdf_randomx_thread_arg.walletBuffer = walletBufferStack;
	// NOTE VDF_SHA_HASH_SIZE == RANDOMX_HASH_SIZE
	_vdf_randomx_thread_arg.seed = seed;
	_vdf_randomx_thread_arg.vmPtr = vmPtr;
	_vdf_randomx_thread_arg.outCheckpoint = outCheckpoint + (checkpointCount+1)*VDF_SHA_HASH_SIZE;
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

////////////////////////////////////////////////////////////////////////////////////////////////////
//    Verify SHA
////////////////////////////////////////////////////////////////////////////////////////////////////
void _vdf_sha_verify_thread(vdf_sha_verify_thread_arg* _arg) {
	vdf_sha_verify_thread_arg* arg = _arg;
	while(true) {
		if (!arg->job->verifyRes) {
			return;
		}

		unsigned char expdOut[VDF_SHA_HASH_SIZE];
		unsigned char* in = arg->checkpointIdx == 0 ? arg->job->seed : (arg->job->inCheckpointSha + (arg->checkpointIdx-1)*VDF_SHA_HASH_SIZE);
		unsigned char* out = arg->job->inCheckpointSha + arg->checkpointIdx*VDF_SHA_HASH_SIZE;
		_vdf_sha2(arg->job->walletBuffer, in, expdOut, NULL, 0, arg->job->hashingIterationsSha);
		// 0 == equal
		if (0 != memcmp(expdOut, out, VDF_SHA_HASH_SIZE)) {
			arg->job->verifyRes = false;
			return;
		}

		{
			const std::lock_guard<std::mutex> lock(arg->job->lock);

			bool found = false;
			for(int i=arg->checkpointIdx+1;i<arg->job->checkpointCount;i++) {
				vdf_sha_verify_thread_arg* new_arg = &arg->job->_vdf_sha_verify_thread_arg_list[i];
				if (!new_arg->in_progress) {
					new_arg->in_progress = true;
					arg = new_arg;
					found = true;
					break;
				}
			}
			if (!found) break;
		}
	}

	// TODO steal job from other hash function
}

bool vdf_parallel_sha_verify(unsigned char* walletBuffer, unsigned char* seed, int checkpointCount, int hashingIterations, unsigned char* inRes, unsigned char* inCheckpoint, int maxThreadCount) {
	int freeThreadCount = maxThreadCount;

	vdf_verify_job job;
	job.walletBuffer = walletBuffer;
	job.seed = seed;
	job.inCheckpointSha = inCheckpoint;
	job.checkpointCount = checkpointCount;
	job.hashingIterationsSha = hashingIterations;
	job.verifyRes = true;

	job._vdf_sha_verify_thread_arg_list    .resize(checkpointCount);

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_sha_verify_thread_arg*     _vdf_sha_verify_thread_arg     = &job._vdf_sha_verify_thread_arg_list[checkpointIdx];
		_vdf_sha_verify_thread_arg    ->checkpointIdx = checkpointIdx;
		_vdf_sha_verify_thread_arg    ->thread = NULL;
		_vdf_sha_verify_thread_arg    ->in_progress = false;
		_vdf_sha_verify_thread_arg    ->job = &job;
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_sha_verify_thread_arg*     _vdf_sha_verify_thread_arg     = &job._vdf_sha_verify_thread_arg_list[checkpointIdx];
		if (freeThreadCount > 0) {
			freeThreadCount--;
			const std::lock_guard<std::mutex> lock(job.lock);
			_vdf_sha_verify_thread_arg->in_progress = true;
			_vdf_sha_verify_thread_arg->thread = new std::thread(_vdf_sha_verify_thread, _vdf_sha_verify_thread_arg);
		}
		if (freeThreadCount == 0) break;
	}

	if (job.verifyRes) {
		unsigned char expdOut[VDF_SHA_HASH_SIZE];
		unsigned char* sha_temp_result = inCheckpoint + (checkpointCount-1)*VDF_SHA_HASH_SIZE;

		_vdf_sha2(walletBuffer, sha_temp_result, expdOut, NULL, 0, hashingIterations);
		if (0 != memcmp(expdOut, inRes, VDF_SHA_HASH_SIZE)) {
			job.verifyRes = false;
		}
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_sha_verify_thread_arg*     _vdf_sha_verify_thread_arg     = &job._vdf_sha_verify_thread_arg_list[checkpointIdx];

		if (_vdf_sha_verify_thread_arg->thread) {
			_vdf_sha_verify_thread_arg->thread->join();
			free(_vdf_sha_verify_thread_arg->thread);
		}
	}

	return job.verifyRes;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    Verify Randomx
////////////////////////////////////////////////////////////////////////////////////////////////////
void _vdf_randomx_verify_thread(vdf_randomx_verify_thread_arg* _arg) {
	struct vdf_randomx_verify_thread_arg* arg = _arg;
	while(true) {
		if (!arg->job->verifyRes) {
			return;
		}

		unsigned char expdOut[RANDOMX_HASH_SIZE];
		unsigned char* in = arg->checkpointIdx == 0 ? arg->job->seed : (arg->job->inCheckpointRandomx + (arg->checkpointIdx-1)*RANDOMX_HASH_SIZE);
		unsigned char* out = arg->job->inCheckpointRandomx + arg->checkpointIdx*RANDOMX_HASH_SIZE;
		vdf_randomx(arg->job->walletBuffer, in, expdOut, NULL, 0, arg->job->hashingIterationsRandomx, arg->vmPtr);
		// 0 == equal
		if (0 != memcmp(expdOut, out, RANDOMX_HASH_SIZE)) {
			arg->job->verifyRes = false;
			return;
		}

		{
			const std::lock_guard<std::mutex> lock(arg->job->lock);

			bool found = false;
			for(int i=arg->checkpointIdx+1;i<arg->job->checkpointCount;i++) {
				struct vdf_randomx_verify_thread_arg* new_arg = &arg->job->_vdf_randomx_verify_thread_arg_list[i];
				if (!new_arg->in_progress) {
					new_arg->in_progress = true;
					new_arg->vmPtr = arg->vmPtr;
					arg->vmPtr = NULL;
					arg = new_arg;
					found = true;
					break;
				}
			}
			if (!found) break;
		}
	}

	// TODO steal job from other hash function
}

bool vdf_parallel_randomx_verify(unsigned char* walletBuffer, unsigned char* seed, int checkpointCount, int hashingIterations, unsigned char* inRes, unsigned char* inCheckpoint, int maxThreadCount,
	randomx_dataset* datasetPtr, randomx_cache* cachePtr, randomx_vm *vmPtr, randomx_flags flags) {
	int freeThreadCount = maxThreadCount;

	vdf_verify_job job;
	job.walletBuffer = walletBuffer;
	job.seed = seed;
	job.inCheckpointRandomx = inCheckpoint;
	job.checkpointCount = checkpointCount;
	job.hashingIterationsRandomx = hashingIterations;
	job.verifyRes = true;

	job._vdf_randomx_verify_thread_arg_list.resize(checkpointCount);

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];
		_vdf_randomx_verify_thread_arg->checkpointIdx = checkpointIdx;
		_vdf_randomx_verify_thread_arg->thread = NULL;
		_vdf_randomx_verify_thread_arg->in_progress = false;
		_vdf_randomx_verify_thread_arg->job = &job;
		_vdf_randomx_verify_thread_arg->vmPtr = NULL;
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];
		if (freeThreadCount > 0) {
			freeThreadCount--;
			const std::lock_guard<std::mutex> lock(job.lock);
			_vdf_randomx_verify_thread_arg->vmPtr = randomx_create_vm(flags, cachePtr, datasetPtr);
			if (_vdf_randomx_verify_thread_arg->vmPtr == NULL) {
				job.verifyRes = false;
				break;
			}
			_vdf_randomx_verify_thread_arg->in_progress = true;
			_vdf_randomx_verify_thread_arg->thread = new std::thread(_vdf_randomx_verify_thread, _vdf_randomx_verify_thread_arg);
		}
		if (freeThreadCount == 0) break;
	}

	if (job.verifyRes) {
		// unsigned char expdOut[VDF_SHA_HASH_SIZE];
		// unsigned char* sha_temp_result = inCheckpoint + (checkpointCount-1)*VDF_SHA_HASH_SIZE;

		// vdf_randomx(walletBuffer, sha_temp_result, expdOut, NULL, 0, hashingIterations);
		// if (0 != memcmp(expdOut, inRes, VDF_SHA_HASH_SIZE)) {
			// job.verifyRes = false;
		// }
		unsigned char expdOut[RANDOMX_HASH_SIZE];
		unsigned char* randomx_temp_result = inCheckpoint + (checkpointCount-1)*RANDOMX_HASH_SIZE;

		vdf_randomx(walletBuffer, randomx_temp_result, expdOut, NULL, 0, hashingIterations, vmPtr);
		if (0 != memcmp(expdOut, inRes, RANDOMX_HASH_SIZE)) {
			job.verifyRes = false;
		}
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];

		if (_vdf_randomx_verify_thread_arg->thread) {
			_vdf_randomx_verify_thread_arg->thread->join();
			free(_vdf_randomx_verify_thread_arg->thread);
		}
	}

	return job.verifyRes;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    Verify SHA+Randomx
////////////////////////////////////////////////////////////////////////////////////////////////////
// NOTE freeThreadCount should be >= 2
// Thread count not divisible by 2 is suboptimal by design
// NOTE state is already locked
bool vdf_parallel_sha_randomx_verify(unsigned char* walletBuffer, unsigned char* seed, int _checkpointCount, int hashingIterationsSha, int hashingIterationsRandomx,
	unsigned char* inRes, unsigned char* inCheckpoint, int maxThreadCount, randomx_dataset* datasetPtr, randomx_cache* cachePtr, randomx_vm *vmPtr, randomx_flags flags) {
	int freeThreadCount = maxThreadCount;
	int checkpointCount = _checkpointCount+1;

	vdf_verify_job job;
	job.walletBuffer = walletBuffer;
	job.seed = seed;
	job.inCheckpointSha = inCheckpoint;
	job.inCheckpointRandomx = inCheckpoint + checkpointCount*VDF_SHA_HASH_SIZE;
	job.checkpointCount = checkpointCount;
	job.hashingIterationsSha = hashingIterationsSha;
	job.hashingIterationsRandomx = hashingIterationsRandomx;
	job.verifyRes = true;
	job.flags = flags;

	job._vdf_sha_verify_thread_arg_list    .resize(checkpointCount);
	job._vdf_randomx_verify_thread_arg_list.resize(checkpointCount);

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_sha_verify_thread_arg*     _vdf_sha_verify_thread_arg     = &job._vdf_sha_verify_thread_arg_list[checkpointIdx];
		_vdf_sha_verify_thread_arg    ->checkpointIdx = checkpointIdx;
		_vdf_sha_verify_thread_arg    ->thread = NULL;
		_vdf_sha_verify_thread_arg    ->in_progress = false;
		_vdf_sha_verify_thread_arg    ->job = &job;

		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];
		_vdf_randomx_verify_thread_arg->checkpointIdx = checkpointIdx;
		_vdf_randomx_verify_thread_arg->thread = NULL;

		_vdf_randomx_verify_thread_arg->in_progress = false;
		_vdf_randomx_verify_thread_arg->job = &job;
		_vdf_randomx_verify_thread_arg->vmPtr = NULL;
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_sha_verify_thread_arg*     _vdf_sha_verify_thread_arg     = &job._vdf_sha_verify_thread_arg_list[checkpointIdx];
		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];
		if (freeThreadCount > 0) {
			freeThreadCount--;
			const std::lock_guard<std::mutex> lock(job.lock);
			_vdf_sha_verify_thread_arg->in_progress = true;
			_vdf_sha_verify_thread_arg->thread = new std::thread(_vdf_sha_verify_thread, _vdf_sha_verify_thread_arg);
		}

		if (freeThreadCount > 0) {
			freeThreadCount--;
			const std::lock_guard<std::mutex> lock(job.lock);
			_vdf_randomx_verify_thread_arg->vmPtr = randomx_create_vm(flags, cachePtr, datasetPtr);
			if (_vdf_randomx_verify_thread_arg->vmPtr == NULL) {
				job.verifyRes = false;
				break;
			}
			_vdf_randomx_verify_thread_arg->in_progress = true;
			_vdf_randomx_verify_thread_arg->thread = new std::thread(_vdf_randomx_verify_thread, _vdf_randomx_verify_thread_arg);
		}
		if (freeThreadCount == 0) break;
	}

	if (job.verifyRes) {
		unsigned char expdOut[VDF_SHA_HASH_SIZE];
		unsigned char* sha_temp_result = inCheckpoint + (checkpointCount-1)*VDF_SHA_HASH_SIZE;
		unsigned char* randomx_temp_result = inCheckpoint + checkpointCount*VDF_SHA_HASH_SIZE + + (checkpointCount-1)*RANDOMX_HASH_SIZE;

		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, sha_temp_result, VDF_SHA_HASH_SIZE);
		SHA256_Update(&sha256, randomx_temp_result, RANDOMX_HASH_SIZE);
		SHA256_Final(expdOut, &sha256);

		if (0 != memcmp(expdOut, inRes, VDF_SHA_HASH_SIZE)) {
			job.verifyRes = false;
		}
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_sha_verify_thread_arg*     _vdf_sha_verify_thread_arg     = &job._vdf_sha_verify_thread_arg_list[checkpointIdx];
		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];

		if (_vdf_sha_verify_thread_arg->thread) {
			_vdf_sha_verify_thread_arg->thread->join();
			free(_vdf_sha_verify_thread_arg->thread);
		}
		if (_vdf_randomx_verify_thread_arg->thread) {
			_vdf_randomx_verify_thread_arg->thread->join();
			free(_vdf_randomx_verify_thread_arg->thread);
		}
	}

	for (int checkpointIdx=0;checkpointIdx<checkpointCount;checkpointIdx++) {
		struct vdf_randomx_verify_thread_arg* _vdf_randomx_verify_thread_arg = &job._vdf_randomx_verify_thread_arg_list[checkpointIdx];
		if (_vdf_randomx_verify_thread_arg->vmPtr) {
			randomx_destroy_vm(_vdf_randomx_verify_thread_arg->vmPtr);
		}
	}

	return job.verifyRes;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    MIMC
////////////////////////////////////////////////////////////////////////////////////////////////////
// https://www.youtube.com/watch?v=uXa-NwbRDU0

#define vdf_mimc_len_round_constants 64
mpz_t vdf_mimc_round_constants[vdf_mimc_len_round_constants];

mpz_t vdf_mimc_modulus;
mpz_t vdf_mimc_pow;
mpz_t vdf_mimc_little_fermat_pow;
void vdf_mimc_init(mpz_t modulus, mpz_t pow) {
  mpz_init_set(vdf_mimc_modulus, modulus);
  mpz_init_set(vdf_mimc_pow, pow);
  
  mpz_t t0, t1;
  mpz_init(t0);
  mpz_init(t1);
  
  mpz_mul_ui(t1, vdf_mimc_modulus, 2);
  mpz_sub_ui(t0, t1, 1);
  mpz_div_ui(vdf_mimc_little_fermat_pow, t0, 3);
  
  // Note this part is missing in https://www.youtube.com/watch?v=uXa-NwbRDU0 , but it probably can improve protection from
  //   https://eprint.iacr.org/2016/492.pdf 4.2 Security analysis -> Interpolation Attack
  mpz_t FORTYTWO;
  mpz_init(FORTYTWO);
  mpz_set_ui(FORTYTWO, 42);
  for (unsigned long i = 0; i < vdf_mimc_len_round_constants; i++) {
    mpz_init(vdf_mimc_round_constants[i]);
    mpz_ui_pow_ui(t0, i, 7);
    mpz_xor(vdf_mimc_round_constants[i], t0, FORTYTWO);
  }
}

void vdf_mimc_import(unsigned char* seed, unsigned char* out) {
  mpz_t t0;
  mpz_init(t0);
  mpz_t input;
  // MSB [0]
  mpz_import(input, VDF_MIMC_SIZE, 1, sizeof(seed[0]), 0, 0, seed);
  mpz_mod(t0, input, vdf_mimc_modulus);
  memset(out, 0, VDF_MIMC_SIZE);
  size_t countp;
  mpz_export(out, &countp, 1, 1, 0, 0, t0);
}

// NOTE pitfall. vdf_mimc_import(seed) is optional here, but mandatory in vdf_mimc_verify
void vdf_mimc_slow(unsigned char* seed, unsigned char* out, int iterations) {
  mpz_t t0, t1;
  mpz_init(t0);
  mpz_init(t1);
  
  mpz_t input;
  // MSB [0]
  mpz_import(input, VDF_MIMC_SIZE, 1, sizeof(seed[0]), 0, 0, seed);
  for (int i = 1; i < iterations; i++) {
    // why not mpz_powm ?
    mpz_pow_ui(t0, input, 3);
    mpz_add(t1, t0, vdf_mimc_round_constants[i%vdf_mimc_len_round_constants]);
    mpz_mod(input, t1, vdf_mimc_modulus);
  }
  memset(out, 0, VDF_MIMC_SIZE);
  size_t countp;
  mpz_export(out, &countp, 1, 1, 0, 0, input);
}

// NOTE seed_expd can be more than p, first iteration should use vdf_mimc_import(seed_expd)
bool vdf_mimc_verify(unsigned char* seed_expd, unsigned char* out, int iterations) {
  mpz_t t0, t1;
  mpz_init(t0);
  mpz_init(t1);
  
  mpz_t input;
  // MSB [0]
  mpz_import(input, VDF_MIMC_SIZE, 1, sizeof(out[0]), 0, 0, out);
  for (int i = iterations - 1; i > 0; i--) {
    mpz_sub(t0, input, vdf_mimc_round_constants[i%vdf_mimc_len_round_constants]);
    mpz_powm(input, t0, vdf_mimc_little_fermat_pow, vdf_mimc_modulus);
  }
  unsigned char seed_real[VDF_MIMC_SIZE] = {0};
  size_t countp;
  mpz_export(seed_real, &countp, 1, 1, 0, 0, input);
  
  return 0 == memcmp(seed_real, seed_expd, VDF_MIMC_SIZE);
}
