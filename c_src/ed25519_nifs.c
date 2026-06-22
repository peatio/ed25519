#define SIGNATURE_SIZE 64
#define PUBLIC_KEY_SIZE 32
#define SECRET_KEY_SIZE 64
#define SEED_SIZE 32
#include "ed25519.h"
#include "erl_nif.h"
#include "erl_nif_compat.h"
// prototypes
ERL_NIF_TERM ed25519_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_keypair_with_seed(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_derive_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_sign_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_sign_bytom_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_sign_mixin_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_verify_sig(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_verify_sig(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_hash(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, char *error);

// lifecycle
int load(ErlNifEnv* env, void ** priv_data, ERL_NIF_TERM load_info);
int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info);
int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info);
void unload(ErlNifEnv* env, void* priv);

static ErlNifFunc nif_funcs[] = 
{
	{"keypair", 0, ed25519_keypair},
	{"keypair", 1, ed25519_keypair_with_seed},
	{"public_key", 1, ed25519_derive_public_key},
	{"sign", 2, ed25519_sign_msg},
	{"sign_bytom", 2, ed25519_sign_bytom_msg},
	{"sign_mixin", 2, ed25519_sign_mixin_msg},
	{"verify", 3, ed25519_verify_sig}
};

ERL_NIF_INIT(ed25519, nif_funcs, load, NULL, NULL, NULL)

int load(ErlNifEnv* env, void ** priv_data, ERL_NIF_TERM load_info)
{
	return 0;
}

int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
	return 0;
}

int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info)
{
	return 0;
}

void unload(ErlNifEnv* env, void* priv)
{
	return;
}

ERL_NIF_TERM ed25519_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary secret;
	ErlNifBinary public;
	ErlNifBinary seed;
	// handle badarg

	if (!enif_alloc_binary(SECRET_KEY_SIZE, &secret)){
		return make_error_tuple(env, "alloc_secret_failed");
	}

	if (!enif_alloc_binary(PUBLIC_KEY_SIZE, &public)){
		return make_error_tuple(env, "alloc_public_failed");
	}

	if (!enif_alloc_binary(SEED_SIZE, &seed)){
		return make_error_tuple(env, "alloc_seed_failed");
	}

	// todo pointer release review
	ed25519_create_seed(seed.data);
	int result = ed25519_create_keypair(public.data, secret.data, seed.data);
	if (result!=0){
		return make_error_tuple(env, "ed25519_create_keypair_failed");
	}else{
		return enif_make_tuple3(env, 
				enif_make_atom(env, "ok"), 
				enif_make_binary(env, &secret),
				enif_make_binary(env, &public));
	}

}

ERL_NIF_TERM ed25519_keypair_with_seed(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary secret;
	ErlNifBinary public;
	ErlNifBinary seed;
	// handle badarg
	if (argc!=1 || !enif_inspect_binary(env, argv[0], &seed)
			|| seed.size != SEED_SIZE){
		return enif_make_badarg(env);
	}
	if (!enif_alloc_binary(SECRET_KEY_SIZE, &secret)){
		return make_error_tuple(env, "alloc_secret_failed");
	}

	if (!enif_alloc_binary(PUBLIC_KEY_SIZE, &public)){
		return make_error_tuple(env, "alloc_public_failed");
	}

	int result = ed25519_create_keypair(public.data, secret.data, seed.data);
	if (result!=0){
		return make_error_tuple(env, "ed25519_create_keypair_failed");
	}else{
		return enif_make_tuple3(env, 
				enif_make_atom(env, "ok"), 
				enif_make_binary(env, &secret),
				enif_make_binary(env, &public));
	}

}




ERL_NIF_TERM ed25519_derive_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
	ErlNifBinary secret;
	ErlNifBinary public;
	enif_inspect_binary(env, argv[0], &secret);	
	if (!enif_alloc_binary(PUBLIC_KEY_SIZE, &public)){
		return make_error_tuple(env, "alloc_public_failed");
	}
	int result = ed25519_public_key(public.data,secret.data);
	if (result!=0){
		return make_error_tuple(env, "ed25519_public_key");
	}else{
		return enif_make_tuple2(env, 
				enif_make_atom(env, "ok"), 
				enif_make_binary(env, &public));
	}


}


ERL_NIF_TERM ed25519_sign_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary signature;
	ErlNifBinary message;
	ErlNifBinary secret;
	unsigned char public[PUBLIC_KEY_SIZE];

	if((argc !=2)	|| (!enif_inspect_binary(env, argv[0], &message)) 
			|| (!enif_inspect_binary(env, argv[1], &secret))
			|| (secret.size != SECRET_KEY_SIZE)) {
		return enif_make_badarg(env);
	}

	if (ed25519_public_key(public, secret.data) != 0) {
		return make_error_tuple(env, "ed25519_public_key_failed");
	}

	if (!enif_alloc_binary(SIGNATURE_SIZE, &signature)) {
		return make_error_tuple(env, "signature_alloc_failed");
	}
	int result = ed25519_sign(signature.data, message.data, message.size, secret.data);
	if(result!=0){
        	return make_error_tuple(env, "ed25519_sign_msg_failed");
	}else{
		return enif_make_tuple2(env, 
				enif_make_atom(env, "ok"), 
				enif_make_binary(env, &signature));
	}
}

ERL_NIF_TERM ed25519_sign_bytom_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary signature;
	ErlNifBinary message;
	ErlNifBinary secret;
	unsigned char public[PUBLIC_KEY_SIZE];

	if((argc !=2)	|| (!enif_inspect_binary(env, argv[0], &message))
			|| (!enif_inspect_binary(env, argv[1], &secret))
			|| (secret.size != SECRET_KEY_SIZE)) {
		return enif_make_badarg(env);
	}

	if (ed25519_public_key(public, secret.data) != 0) {
		return make_error_tuple(env, "ed25519_public_key_failed");
	}

	if (!enif_alloc_binary(SIGNATURE_SIZE, &signature)) {
		return make_error_tuple(env, "signature_alloc_failed");
	}
	int result = ed25519_sign_bytom(signature.data, message.data, message.size, secret.data);
	if(result!=0){
        	return make_error_tuple(env, "ed25519_sign_msg_failed");
	}else{
		return enif_make_tuple2(env,
				enif_make_atom(env, "ok"),
				enif_make_binary(env, &signature));
	}
}

ERL_NIF_TERM ed25519_sign_mixin_msg(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary signature;
	ErlNifBinary message;
	ErlNifBinary secret;
	unsigned char public[PUBLIC_KEY_SIZE];

	if((argc !=2)	|| (!enif_inspect_binary(env, argv[0], &message))
			|| (!enif_inspect_binary(env, argv[1], &secret))
			|| (secret.size != SECRET_KEY_SIZE)) {
		return enif_make_badarg(env);
	}

	if (ed25519_public_key(public, secret.data) != 0) {
		return make_error_tuple(env, "ed25519_public_key_failed");
	}

	if (!enif_alloc_binary(SIGNATURE_SIZE, &signature)) {
		return make_error_tuple(env, "signature_alloc_failed");
	}
	int result = ed25519_sign_mixin(signature.data, message.data, message.size, secret.data);
	if(result!=0){
        	return make_error_tuple(env, "ed25519_sign_msg_failed");
	}else{
		return enif_make_tuple2(env,
				enif_make_atom(env, "ok"),
				enif_make_binary(env, &signature));
	}
}

ERL_NIF_TERM ed25519_verify_sig(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{	
	ErlNifBinary signature;
	ErlNifBinary message;
	ErlNifBinary public;
	if( argc != 3 || !enif_inspect_binary(env, argv[0], &signature)
			|| !enif_inspect_binary(env, argv[1], &message)
			|| !enif_inspect_binary(env, argv[2], &public)
			|| signature.size != SIGNATURE_SIZE
			|| public.size != PUBLIC_KEY_SIZE){
		return enif_make_badarg(env);
	}
	int result = ed25519_verify(signature.data, message.data, message.size, public.data);
	if(result == 1){
		return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_atom(env, "true"));
	}else if(result == 0){
		return enif_make_tuple2(env, enif_make_atom(env, "ok"), enif_make_atom(env, "false"));
	}else{
		return make_error_tuple(env, "ed25519_verify_sig_failed");
	}
}

ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, char *error)
{
	return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error));
}


