#ifndef CRYPTO_H__
#define CRYPTO_H__

#include <inttypes.h>
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/dsa.h>
#include <openssl/ecdsa.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

#include "base.hpp"
#include "tag.hpp"
#include "cpu.hpp"

namespace i2p
{
namespace crypto
{
	bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len);

	// DSA
	DSA * CreateDSA ();

	// RSA
	const BIGNUM * GetRSAE ();

	// DH
	class DHKeys
	{
		public:

			DHKeys ();
			~DHKeys ();

			void GenerateKeys ();
			const uint8_t * GetPublicKey () const { return m_PublicKey; };
			void Agree (const uint8_t * pub, uint8_t * shared);

		private:

			DH * m_DH;
			uint8_t m_PublicKey[256];
	};

	// ElGamal
	void ElGamalEncrypt (const uint8_t * key, const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding = false);
	bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted, uint8_t * data, BN_CTX * ctx, bool zeroPadding = false);
	void GenerateElGamalKeyPair (uint8_t * priv, uint8_t * pub);

	void InitCrypto (bool precomputation=false);
	void TerminateCrypto ();
}
}

// take care about openssl version
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x010100000) || defined(LIBRESSL_VERSION_NUMBER) // 1.1.0 or LibreSSL
// define getters and setters introduced in 1.1.0
inline int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
	{
		if (d->p) BN_free (d->p);
		if (d->q) BN_free (d->q);
		if (d->g) BN_free (d->g);
		d->p = p; d->q = q; d->g = g; return 1;
	}
inline int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
	{
		if (d->pub_key) BN_free (d->pub_key);
		if (d->priv_key) BN_free (d->priv_key);
		d->pub_key = pub_key; d->priv_key = priv_key; return 1;
	}
inline void DSA_get0_key(const DSA *d, const BIGNUM **pub_key, const BIGNUM **priv_key)
	{ *pub_key = d->pub_key; *priv_key = d->priv_key; }
inline int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s)
	{
		if (sig->r) BN_free (sig->r);
		if (sig->s) BN_free (sig->s);
		sig->r = r; sig->s = s; return 1;
	}
inline void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
	{ *pr = sig->r; *ps = sig->s; }

inline int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
	{
		if (sig->r) BN_free (sig->r);
		if (sig->s) BN_free (sig->s);
		sig->r = r; sig->s = s; return 1;
	}
inline void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
	{ *pr = sig->r; *ps = sig->s; }

inline int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
	{
		if (r->n) BN_free (r->n);
		if (r->e) BN_free (r->e);
		if (r->d) BN_free (r->d);
		r->n = n; r->e = e; r->d = d; return 1;
	}
inline void RSA_get0_key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
	{ *n = r->n; *e = r->e; *d = r->d; }

inline int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
	{
		if (dh->p) BN_free (dh->p);
		if (dh->q) BN_free (dh->q);
		if (dh->g) BN_free (dh->g);
		dh->p = p; dh->q = q; dh->g = g;  return 1;
	}
inline int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
	{
		if (dh->pub_key) BN_free (dh->pub_key);
		if (dh->priv_key) BN_free (dh->priv_key);
		dh->pub_key = pub_key; dh->priv_key = priv_key; return 1;
	}
inline void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
	{ *pub_key = dh->pub_key; *priv_key = dh->priv_key; }

inline RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey)
{ return pkey->pkey.rsa; }

inline EVP_MD_CTX *EVP_MD_CTX_new ()
	{ return EVP_MD_CTX_create(); }
inline void EVP_MD_CTX_free (EVP_MD_CTX *ctx)
	{ EVP_MD_CTX_destroy (ctx); }

// ssl
#define TLS_method TLSv1_method

#endif

#endif
