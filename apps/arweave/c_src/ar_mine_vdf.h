////////////////////////////////////////////////////////////////////////////////////////////////////
//    SHA
////////////////////////////////////////////////////////////////////////////////////////////////////
static ERL_NIF_TERM vdf_sha2_nif(ErlNifEnv* envPtr, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary WalletBinary, Seed;
	int checkpointCount;
	int hashingIterations;

	if (argc != 4) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != VDF_SHA_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &checkpointCount)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &hashingIterations)) {
		return enif_make_badarg(envPtr);
	}

	unsigned char temp_result[VDF_SHA_HASH_SIZE];
	size_t outCheckpointSize = VDF_SHA_HASH_SIZE*checkpointCount;
	ERL_NIF_TERM outputTermCheckpoint;
	unsigned char* outCheckpoint = enif_make_new_binary(envPtr, outCheckpointSize, &outputTermCheckpoint);
	vdf_sha2(WalletBinary.data, Seed.data, temp_result, outCheckpoint, checkpointCount, hashingIterations);

	return ok_tuple2(envPtr, make_output_binary(envPtr, temp_result, VDF_SHA_HASH_SIZE), outputTermCheckpoint);
}

static ERL_NIF_TERM vdf_parallel_sha_verify_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	ErlNifBinary WalletBinary, Seed, InCheckpoint, InRes;
	int checkpointCount;
	int hashingIterations;
	int maxThreadCount;

	if (argc != 7) {
		return enif_make_badarg(envPtr);
	}

	// copypasted from vdf_sha2_nif
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &checkpointCount)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &hashingIterations)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[4], &InCheckpoint)) {
		return enif_make_badarg(envPtr);
	}
	if (InCheckpoint.size != checkpointCount*VDF_SHA_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[5], &InRes)) {
		return enif_make_badarg(envPtr);
	}
	if (InRes.size != VDF_SHA_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[6], &maxThreadCount)) {
		return enif_make_badarg(envPtr);
	}
	if (maxThreadCount < 1) {
		return enif_make_badarg(envPtr);
	}

	// NOTE last paramemter will be array later
	bool res = vdf_parallel_sha_verify(WalletBinary.data, Seed.data, checkpointCount, hashingIterations, InRes.data, InCheckpoint.data, maxThreadCount);
	if (!res) {
		return error(envPtr, "verification failed");
	}

	return enif_make_atom(envPtr, "ok");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    Randomx
////////////////////////////////////////////////////////////////////////////////////////////////////
static ERL_NIF_TERM vdf_randomx_create_vm_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	ERL_NIF_TERM resource;
	randomx_flags flags;
	int fast, jitEnabled, largePagesEnabled, hardwareAESEnabled;
	struct state* statePtr;

	if (argc != 5) {
		return enif_make_badarg(envPtr);
	}

	if (!enif_get_resource(envPtr, argv[0], stateType, (void**) &statePtr)) {
		return error(envPtr, "failed to read state");
	}
	if (!enif_get_int(envPtr, argv[1], &fast)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &jitEnabled)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &largePagesEnabled)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[4], &hardwareAESEnabled)) {
		return enif_make_badarg(envPtr);
	}

	flags = RANDOMX_FLAG_DEFAULT;
	if (fast) {
		flags |= RANDOMX_FLAG_FULL_MEM;
	}
	if (hardwareAESEnabled) {
		flags |= RANDOMX_FLAG_HARD_AES;
	}
	if (jitEnabled) {
		flags |= RANDOMX_FLAG_JIT;
	}
	if (largePagesEnabled) {
		flags |= RANDOMX_FLAG_LARGE_PAGES;
	}

	enif_rwlock_rlock(statePtr->lockPtr);
	if (statePtr->isRandomxReleased != 0) {
		enif_rwlock_runlock(statePtr->lockPtr);
		return error(envPtr, "state has been released");
	}
	randomx_vm *vmPtr = randomx_create_vm(flags, statePtr->cachePtr, statePtr->datasetPtr);
	vmPtr = randomx_create_vm(flags, statePtr->cachePtr, statePtr->datasetPtr);
	if (vmPtr == NULL) {
		enif_rwlock_runlock(statePtr->lockPtr);
		return error(envPtr, "randomx_create_vm failed");
	}

	enif_rwlock_runlock(statePtr->lockPtr);

	struct wrap_randomx_vm *wrapVm = enif_alloc_resource(vdfRandomxVmType, sizeof(struct wrap_randomx_vm));
	wrapVm->flags = flags;
	wrapVm->vmPtr = vmPtr;
	resource = enif_make_resource(envPtr, wrapVm);
	enif_release_resource(wrapVm);

	return ok_tuple(envPtr, resource);
}

static ERL_NIF_TERM vdf_randomx_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	struct wrap_randomx_vm *wrapVm;
	unsigned char hashPtr[RANDOMX_HASH_SIZE];
	struct state* statePtr;

	ErlNifBinary WalletBinary, Seed;
	int checkpointCount;
	int hashingIterations;

	if (argc != 6) {
		return enif_make_badarg(envPtr);
	}

	// copypasted from vdf_sha2_nif
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &checkpointCount)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &hashingIterations)) {
		return enif_make_badarg(envPtr);
	}

	if (!enif_get_resource(envPtr, argv[4], stateType, (void**) &statePtr)) {
		return error(envPtr, "failed to read state");
	}
	if (!enif_get_resource(envPtr, argv[5], vdfRandomxVmType, (void**) &wrapVm)) {
		return error(envPtr, "failed to read vm");
	}

	size_t outCheckpointSize = RANDOMX_HASH_SIZE*checkpointCount;
	ERL_NIF_TERM outputTermCheckpoint;
	unsigned char* outCheckpoint = enif_make_new_binary(envPtr, outCheckpointSize, &outputTermCheckpoint);
	enif_rwlock_rlock(statePtr->lockPtr);
	vdf_randomx(WalletBinary.data, Seed.data, hashPtr, outCheckpoint, checkpointCount, hashingIterations, wrapVm->vmPtr);
	enif_rwlock_runlock(statePtr->lockPtr);

	return ok_tuple2(envPtr, make_output_binary(envPtr, hashPtr, RANDOMX_HASH_SIZE), outputTermCheckpoint);
}

static ERL_NIF_TERM vdf_parallel_randomx_verify_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	struct wrap_randomx_vm *wrapVm;
	struct state* statePtr;

	ErlNifBinary WalletBinary, Seed, InCheckpoint, InRes;
	int checkpointCount;
	int hashingIterations;
	int maxThreadCount;

	if (argc != 9) {
		return enif_make_badarg(envPtr);
	}

	// copypasted from vdf_sha2_nif
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &checkpointCount)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &hashingIterations)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[4], &InCheckpoint)) {
		return enif_make_badarg(envPtr);
	}
	if (InCheckpoint.size != checkpointCount*RANDOMX_HASH_SIZE) {
		return error(envPtr, "FAIL 0");
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[5], &InRes)) {
		return enif_make_badarg(envPtr);
	}
	if (InRes.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[6], &maxThreadCount)) {
		return enif_make_badarg(envPtr);
	}
	if (maxThreadCount < 1) {
		return enif_make_badarg(envPtr);
	}

	if (!enif_get_resource(envPtr, argv[7], stateType, (void**) &statePtr)) {
		return error(envPtr, "failed to read state");
	}
	// temp unused, it's better to send array of wrapVm
	if (!enif_get_resource(envPtr, argv[8], vdfRandomxVmType, (void**) &wrapVm)) {
		return error(envPtr, "failed to read vm");
	}

	enif_rwlock_rlock(statePtr->lockPtr);
	// NOTE last paramemter will be array later
	bool res = vdf_parallel_randomx_verify(WalletBinary.data, Seed.data, checkpointCount, hashingIterations, InRes.data, InCheckpoint.data, maxThreadCount, statePtr->datasetPtr, statePtr->cachePtr, wrapVm->vmPtr, wrapVm->flags);
	enif_rwlock_runlock(statePtr->lockPtr);
	if (!res) {
		return error(envPtr, "verification failed");
	}

	return enif_make_atom(envPtr, "ok");
}


////////////////////////////////////////////////////////////////////////////////////////////////////
//    SHA+Randomx
////////////////////////////////////////////////////////////////////////////////////////////////////
static ERL_NIF_TERM vdf_parallel_sha_randomx_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	struct wrap_randomx_vm *wrapVm;
	struct state* statePtr;

	ErlNifBinary WalletBinary, Seed;
	int checkpointCount;
	int hashingIterationsSha;
	int hashingIterationsRandomx;

	if (argc != 7) {
		return enif_make_badarg(envPtr);
	}

	// copypasted from vdf_sha2_nif
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &checkpointCount)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &hashingIterationsSha)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[4], &hashingIterationsRandomx)) {
		return enif_make_badarg(envPtr);
	}

	if (!enif_get_resource(envPtr, argv[5], stateType, (void**) &statePtr)) {
		return error(envPtr, "failed to read state");
	}
	if (!enif_get_resource(envPtr, argv[6], vdfRandomxVmType, (void**) &wrapVm)) {
		return error(envPtr, "failed to read vm");
	}

	unsigned char temp_result[VDF_SHA_HASH_SIZE];
	size_t outCheckpointSize = (VDF_SHA_HASH_SIZE+RANDOMX_HASH_SIZE)*(checkpointCount+1);
	ERL_NIF_TERM outputTermCheckpoint;
	unsigned char* outCheckpoint = enif_make_new_binary(envPtr, outCheckpointSize, &outputTermCheckpoint);
	enif_rwlock_rlock(statePtr->lockPtr);
	vdf_parallel_sha_randomx(WalletBinary.data, Seed.data, temp_result, outCheckpoint, checkpointCount, hashingIterationsSha, hashingIterationsRandomx, wrapVm->vmPtr);
	enif_rwlock_runlock(statePtr->lockPtr);

	return ok_tuple2(envPtr, make_output_binary(envPtr, temp_result, VDF_SHA_HASH_SIZE), outputTermCheckpoint);
}

static ERL_NIF_TERM vdf_parallel_sha_randomx_verify_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	struct wrap_randomx_vm *wrapVm;
	struct state* statePtr;

	ErlNifBinary WalletBinary, Seed, InCheckpoint, InRes;
	int checkpointCount;
	int hashingIterationsSha;
	int hashingIterationsRandomx;
	int maxThreadCount;

	if (argc != 10) {
		return enif_make_badarg(envPtr);
	}

	// copypasted from vdf_sha2_nif
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &checkpointCount)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[3], &hashingIterationsSha)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[4], &hashingIterationsRandomx)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[5], &InCheckpoint)) {
		return enif_make_badarg(envPtr);
	}
	if (InCheckpoint.size != (checkpointCount+1)*(VDF_SHA_HASH_SIZE+RANDOMX_HASH_SIZE)) {
		return error(envPtr, "FAIL 0");
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[6], &InRes)) {
		return enif_make_badarg(envPtr);
	}
	if (InRes.size != VDF_SHA_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[7], &maxThreadCount)) {
		return enif_make_badarg(envPtr);
	}
	if (maxThreadCount < 2) {
		return enif_make_badarg(envPtr);
	}

	if (!enif_get_resource(envPtr, argv[8], stateType, (void**) &statePtr)) {
		return error(envPtr, "failed to read state");
	}
	// temp unused, it's better to send array of wrapVm
	if (!enif_get_resource(envPtr, argv[9], vdfRandomxVmType, (void**) &wrapVm)) {
		return error(envPtr, "failed to read vm");
	}

	enif_rwlock_rlock(statePtr->lockPtr);
	// NOTE last paramemter will be array later
	bool res = vdf_parallel_sha_randomx_verify(WalletBinary.data, Seed.data, checkpointCount, hashingIterationsSha, hashingIterationsRandomx, InRes.data, InCheckpoint.data, maxThreadCount,
		statePtr->datasetPtr, statePtr->cachePtr, wrapVm->vmPtr, wrapVm->flags);
	enif_rwlock_runlock(statePtr->lockPtr);
	if (!res) {
		return error(envPtr, "verification failed");
	}

	return enif_make_atom(envPtr, "ok");
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//    MIMC
////////////////////////////////////////////////////////////////////////////////////////////////////

static ERL_NIF_TERM vdf_mimc_init_nif(ErlNifEnv* envPtr, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary ModBin, PowBin;

	if (argc != 2) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[0], &ModBin)) {
		return enif_make_badarg(envPtr);
	}
	if (ModBin.size != VDF_MIMC_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &PowBin)) {
		return enif_make_badarg(envPtr);
	}
	if (PowBin.size != VDF_MIMC_SIZE) {
		return enif_make_badarg(envPtr);
	}

	mpz_t mod;
	mpz_import(mod, VDF_MIMC_SIZE, 1, 1, 0, 0, ModBin.data);
	mpz_t pow;
	mpz_import(pow, VDF_MIMC_SIZE, 1, 1, 0, 0, PowBin.data);
	vdf_mimc_init(mod, pow);

	return enif_make_atom(envPtr, "ok");
}

static ERL_NIF_TERM vdf_mimc_slow_nif(ErlNifEnv* envPtr, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary WalletBinary, Seed;
	int iterations;

	if (argc != 3) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != VDF_MIMC_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &iterations)) {
		return enif_make_badarg(envPtr);
	}

	unsigned char temp_result[VDF_MIMC_SIZE];
	{
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, WalletBinary.data, WALLET_SIZE);
		SHA256_Update(&sha256, Seed.data, VDF_MIMC_SIZE); // -1 memcpy
		SHA256_Final(temp_result, &sha256);
	}

	// NOTE vdf_mimc_import and vdf_mimc_slow are ok with same input and output, so less memory on stack
	vdf_mimc_import(temp_result, temp_result);
	vdf_mimc_slow(temp_result, temp_result, iterations);

	return ok_tuple(envPtr, make_output_binary(envPtr, temp_result, VDF_MIMC_SIZE));
}

static ERL_NIF_TERM vdf_mimc_verify_nif(
	ErlNifEnv* envPtr,
	int argc,
	const ERL_NIF_TERM argv[]
) {
	ErlNifBinary WalletBinary, Seed, InRes;
	int iterations;

	if (argc != 4) {
		return enif_make_badarg(envPtr);
	}

	// copypasted from vdf_sha2_nif
	if (!enif_inspect_binary(envPtr, argv[0], &WalletBinary)) {
		return enif_make_badarg(envPtr);
	}
	if (WalletBinary.size != WALLET_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[1], &Seed)) {
		return enif_make_badarg(envPtr);
	}
	if (Seed.size != RANDOMX_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_get_int(envPtr, argv[2], &iterations)) {
		return enif_make_badarg(envPtr);
	}
	if (!enif_inspect_binary(envPtr, argv[3], &InRes)) {
		return enif_make_badarg(envPtr);
	}
	if (InRes.size != VDF_SHA_HASH_SIZE) {
		return enif_make_badarg(envPtr);
	}
	
	unsigned char intermediate_seed[VDF_MIMC_SIZE];
	{
		SHA256_CTX sha256;
		SHA256_Init(&sha256);
		SHA256_Update(&sha256, WalletBinary.data, WALLET_SIZE);
		SHA256_Update(&sha256, Seed.data, VDF_MIMC_SIZE); // -1 memcpy
		SHA256_Final(intermediate_seed, &sha256);
	}
	// NOTE vdf_mimc_import and vdf_mimc_slow are ok with same input and output, so less memory on stack
	vdf_mimc_import(intermediate_seed, intermediate_seed);
	// NOTE last paramemter will be array later
	bool res = vdf_mimc_verify(intermediate_seed, InRes.data, iterations);
	if (!res) {
		return error(envPtr, "verification failed");
	}

	return enif_make_atom(envPtr, "ok");
}
