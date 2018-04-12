#include <string.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <openssl/dh.h>
#include <openssl/md5.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include "crypto.hpp"

namespace i2p
{
namespace crypto
{
	const uint8_t elgp_[256]=
	{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
		0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
		0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
		0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
		0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
		0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
		0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
		0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
		0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
		0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
		0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
		0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
		0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
		0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
		0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
		0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	};

	const int elgg_ = 2;

	const uint8_t dsap_[128]=
	{
		0x9c, 0x05, 0xb2, 0xaa, 0x96, 0x0d, 0x9b, 0x97, 0xb8, 0x93, 0x19, 0x63, 0xc9, 0xcc, 0x9e, 0x8c,
		0x30, 0x26, 0xe9, 0xb8, 0xed, 0x92, 0xfa, 0xd0, 0xa6, 0x9c, 0xc8, 0x86, 0xd5, 0xbf, 0x80, 0x15,
		0xfc, 0xad, 0xae, 0x31, 0xa0, 0xad, 0x18, 0xfa, 0xb3, 0xf0, 0x1b, 0x00, 0xa3, 0x58, 0xde, 0x23,
		0x76, 0x55, 0xc4, 0x96, 0x4a, 0xfa, 0xa2, 0xb3, 0x37, 0xe9, 0x6a, 0xd3, 0x16, 0xb9, 0xfb, 0x1c,
		0xc5, 0x64, 0xb5, 0xae, 0xc5, 0xb6, 0x9a, 0x9f, 0xf6, 0xc3, 0xe4, 0x54, 0x87, 0x07, 0xfe, 0xf8,
		0x50, 0x3d, 0x91, 0xdd, 0x86, 0x02, 0xe8, 0x67, 0xe6, 0xd3, 0x5d, 0x22, 0x35, 0xc1, 0x86, 0x9c,
		0xe2, 0x47, 0x9c, 0x3b, 0x9d, 0x54, 0x01, 0xde, 0x04, 0xe0, 0x72, 0x7f, 0xb3, 0x3d, 0x65, 0x11,
		0x28, 0x5d, 0x4c, 0xf2, 0x95, 0x38, 0xd9, 0xe3, 0xb6, 0x05, 0x1f, 0x5b, 0x22, 0xcc, 0x1c, 0x93
	};

	const uint8_t dsaq_[20]=
	{
		0xa5, 0xdf, 0xc2, 0x8f, 0xef, 0x4c, 0xa1, 0xe2, 0x86, 0x74, 0x4c, 0xd8, 0xee, 0xd9, 0xd2, 0x9d,
		0x68, 0x40, 0x46, 0xb7
	};

	const uint8_t dsag_[128]=
	{
		0x0c, 0x1f, 0x4d, 0x27, 0xd4, 0x00, 0x93, 0xb4, 0x29, 0xe9, 0x62, 0xd7, 0x22, 0x38, 0x24, 0xe0,
		0xbb, 0xc4, 0x7e, 0x7c, 0x83, 0x2a, 0x39, 0x23, 0x6f, 0xc6, 0x83, 0xaf, 0x84, 0x88, 0x95, 0x81,
		0x07, 0x5f, 0xf9, 0x08, 0x2e, 0xd3, 0x23, 0x53, 0xd4, 0x37, 0x4d, 0x73, 0x01, 0xcd, 0xa1, 0xd2,
		0x3c, 0x43, 0x1f, 0x46, 0x98, 0x59, 0x9d, 0xda, 0x02, 0x45, 0x18, 0x24, 0xff, 0x36, 0x97, 0x52,
		0x59, 0x36, 0x47, 0xcc, 0x3d, 0xdc, 0x19, 0x7d, 0xe9, 0x85, 0xe4, 0x3d, 0x13, 0x6c, 0xdc, 0xfc,
		0x6b, 0xd5, 0x40, 0x9c, 0xd2, 0xf4, 0x50, 0x82, 0x11, 0x42, 0xa5, 0xe6, 0xf8, 0xeb, 0x1c, 0x3a,
		0xb5, 0xd0, 0x48, 0x4b, 0x81, 0x29, 0xfc, 0xf1, 0x7b, 0xce, 0x4f, 0x7f, 0x33, 0x32, 0x1c, 0x3c,
		0xb3, 0xdb, 0xb1, 0x4a, 0x90, 0x5e, 0x7b, 0x2b, 0x3e, 0x93, 0xbe, 0x47, 0x08, 0xcb, 0xcc, 0x82
	};

	const int rsae_ = 65537;

	struct CryptoConstants
	{
		// DH/ElGamal
		BIGNUM * elgp;
		BIGNUM * elgg;

		// DSA
		BIGNUM * dsap;
		BIGNUM * dsaq;
		BIGNUM * dsag;

		// RSA
		BIGNUM * rsae;

		CryptoConstants (const uint8_t * elgp_, int elgg_, const uint8_t * dsap_,
			const uint8_t * dsaq_, const uint8_t * dsag_, int rsae_)
		{
			elgp = BN_new ();
			BN_bin2bn (elgp_, 256, elgp);
			elgg = BN_new ();
			BN_set_word (elgg, elgg_);
			dsap = BN_new ();
			BN_bin2bn (dsap_, 128, dsap);
			dsaq = BN_new ();
			BN_bin2bn (dsaq_, 20, dsaq);
			dsag = BN_new ();
			BN_bin2bn (dsag_, 128, dsag);
			rsae = BN_new ();
			BN_set_word (rsae, rsae_);
		}

		~CryptoConstants ()
		{
			BN_free (elgp);  BN_free (elgg); BN_free (dsap); BN_free (dsaq); BN_free (dsag); BN_free (rsae);
		}
	};

	static const CryptoConstants& GetCryptoConstants ()
	{
		static CryptoConstants cryptoConstants (elgp_, elgg_, dsap_, dsaq_, dsag_, rsae_);
		return cryptoConstants;
	}

	bool bn2buf (const BIGNUM * bn, uint8_t * buf, size_t len)
	{
		int offset = len - BN_num_bytes (bn);
		if (offset < 0) return false;
		BN_bn2bin (bn, buf + offset);
		memset (buf, 0, offset);
		return true;
	}

// RSA
	#define rsae GetCryptoConstants ().rsae
	const BIGNUM * GetRSAE ()
	{
		return rsae;
	}

// DSA
	#define dsap GetCryptoConstants ().dsap
	#define dsaq GetCryptoConstants ().dsaq
	#define dsag GetCryptoConstants ().dsag
	DSA * CreateDSA ()
	{
		DSA * dsa = DSA_new ();
		DSA_set0_pqg (dsa, BN_dup (dsap), BN_dup (dsaq), BN_dup (dsag));
		DSA_set0_key (dsa, NULL, NULL);
		return dsa;
	}

// DH/ElGamal

	const int ELGAMAL_SHORT_EXPONENT_NUM_BITS = 226;
	const int ELGAMAL_SHORT_EXPONENT_NUM_BYTES = ELGAMAL_SHORT_EXPONENT_NUM_BITS/8+1;
	const int ELGAMAL_FULL_EXPONENT_NUM_BITS = 2048;
	const int ELGAMAL_FULL_EXPONENT_NUM_BYTES = ELGAMAL_FULL_EXPONENT_NUM_BITS/8;

	#define elgp GetCryptoConstants ().elgp
	#define elgg GetCryptoConstants ().elgg

	static BN_MONT_CTX * g_MontCtx = nullptr;
	static void PrecalculateElggTable (BIGNUM * table[][255], int len) // table is len's array of array of 255 bignums
	{
		if (len <= 0) return;
		BN_CTX * ctx = BN_CTX_new ();
		g_MontCtx = BN_MONT_CTX_new ();
		BN_MONT_CTX_set (g_MontCtx, elgp, ctx);
		auto montCtx = BN_MONT_CTX_new ();
		BN_MONT_CTX_copy (montCtx, g_MontCtx);
		for (int i = 0; i < len; i++)
		{
			table[i][0] = BN_new ();
			if (!i)
				BN_to_montgomery (table[0][0], elgg, montCtx, ctx);
			else
				BN_mod_mul_montgomery (table[i][0], table[i-1][254], table[i-1][0], montCtx, ctx);
			for (int j = 1; j < 255; j++)
			{
				table[i][j] = BN_new ();
				BN_mod_mul_montgomery (table[i][j], table[i][j-1], table[i][0], montCtx, ctx);
			}
		}
		BN_MONT_CTX_free (montCtx);
		BN_CTX_free (ctx);
	}

	static void DestroyElggTable (BIGNUM * table[][255], int len)
	{
		for (int i = 0; i < len; i++)
			for (int j = 0; j < 255; j++)
			{
				BN_free (table[i][j]);
				table[i][j] = nullptr;
			}
		BN_MONT_CTX_free (g_MontCtx);
	}

	static BIGNUM * ElggPow (const uint8_t * exp, int len, BIGNUM * table[][255], BN_CTX * ctx)
	// exp is in Big Endian
	{
		if (len <= 0) return nullptr;
		auto montCtx = BN_MONT_CTX_new ();
		BN_MONT_CTX_copy (montCtx, g_MontCtx);
		BIGNUM * res = nullptr;
		for (int i = 0; i < len; i++)
		{
			if (res)
			{
				if (exp[i])
					BN_mod_mul_montgomery (res, res, table[len-1-i][exp[i]-1], montCtx, ctx);
			}
			else if (exp[i])
				res = BN_dup (table[len-i-1][exp[i]-1]);
		}
		if (res)
			BN_from_montgomery (res, res, montCtx, ctx);
		BN_MONT_CTX_free (montCtx);
		return res;
	}

	static BIGNUM * ElggPow (const BIGNUM * exp, BIGNUM * table[][255], BN_CTX * ctx)
	{
		auto len = BN_num_bytes (exp);
		uint8_t * buf = new uint8_t[len];
		BN_bn2bin (exp, buf);
		auto ret = ElggPow (buf, len, table, ctx);
		delete[] buf;
		return ret;
	}

	static BIGNUM * (* g_ElggTable)[255] = nullptr;

// DH

	DHKeys::DHKeys ()
	{
		m_DH = DH_new ();
		DH_set0_pqg (m_DH, BN_dup (elgp), NULL, BN_dup (elgg));
		DH_set0_key (m_DH, NULL, NULL);
	}

	DHKeys::~DHKeys ()
	{
		DH_free (m_DH);
	}

	void DHKeys::GenerateKeys ()
	{
		BIGNUM * priv_key = NULL, * pub_key = NULL;
#if !defined(__x86_64__) // use short exponent for non x64
		priv_key = BN_new ();
		BN_rand (priv_key, ELGAMAL_SHORT_EXPONENT_NUM_BITS, 0, 1);
#endif
		if (g_ElggTable)
		{
#if defined(__x86_64__)
			priv_key = BN_new ();
			BN_rand (priv_key, ELGAMAL_FULL_EXPONENT_NUM_BITS, 0, 1);
#endif
			auto ctx = BN_CTX_new ();
			pub_key = ElggPow (priv_key, g_ElggTable, ctx);
			DH_set0_key (m_DH, pub_key, priv_key);
			BN_CTX_free (ctx);
		}
		else
		{
			DH_set0_key (m_DH, NULL, priv_key);
			DH_generate_key (m_DH);
			DH_get0_key (m_DH, (const BIGNUM **)&pub_key, (const BIGNUM **)&priv_key);
		}

		bn2buf (pub_key, m_PublicKey, 256);
	}

	void DHKeys::Agree (const uint8_t * pub, uint8_t * shared)
	{
		BIGNUM * pk = BN_bin2bn (pub, 256, NULL);
		DH_compute_key (shared, pk, m_DH);
		BN_free (pk);
	}

// ElGamal
	void ElGamalEncrypt (const uint8_t * key, const uint8_t * data, uint8_t * encrypted, BN_CTX * ctx, bool zeroPadding)
	{
		BN_CTX_start (ctx);
		// everything, but a, because a might come from table
		BIGNUM * k = BN_CTX_get (ctx);
		BIGNUM * y = BN_CTX_get (ctx);
		BIGNUM * b1 = BN_CTX_get (ctx);
		BIGNUM * b = BN_CTX_get (ctx);
		// select random k
#if defined(__x86_64__)
		BN_rand (k, ELGAMAL_FULL_EXPONENT_NUM_BITS, -1, 1); // full exponent for x64
#else
		BN_rand (k, ELGAMAL_SHORT_EXPONENT_NUM_BITS, -1, 1); // short exponent of 226 bits
#endif
		// calculate a
		BIGNUM * a;
		if (g_ElggTable)
			a = ElggPow (k, g_ElggTable, ctx);
		else
		{
			a = BN_new ();
			BN_mod_exp (a, elgg, k, elgp, ctx);
		}

		// restore y from key
		BN_bin2bn (key, 256, y);
		// calculate b1
		BN_mod_exp (b1, y, k, elgp, ctx);
		// create m
		uint8_t m[255];
		m[0] = 0xFF;
		memcpy (m+33, data, 222);
		SHA256 (m+33, 222, m+1);
		// calculate b = b1*m mod p
		BN_bin2bn (m, 255, b);
		BN_mod_mul (b, b1, b, elgp, ctx);
		// copy a and b
		if (zeroPadding)
		{
			encrypted[0] = 0;
			bn2buf (a, encrypted + 1, 256);
			encrypted[257] = 0;
			bn2buf (b, encrypted + 258, 256);
		}
		else
		{
			bn2buf (a, encrypted, 256);
			bn2buf (b, encrypted + 256, 256);
		}
		BN_free (a);
		BN_CTX_end (ctx);
	}

	bool ElGamalDecrypt (const uint8_t * key, const uint8_t * encrypted,
		uint8_t * data, BN_CTX * ctx, bool zeroPadding)
	{
		BN_CTX_start (ctx);
		BIGNUM * x = BN_CTX_get (ctx), * a = BN_CTX_get (ctx), * b = BN_CTX_get (ctx);
		BN_bin2bn (key, 256, x);
		BN_sub (x, elgp, x); BN_sub_word (x, 1); // x = elgp - x- 1
		BN_bin2bn (zeroPadding ? encrypted + 1 : encrypted, 256, a);
		BN_bin2bn (zeroPadding ? encrypted + 258 : encrypted + 256, 256, b);
		// m = b*(a^x mod p) mod p
		BN_mod_exp (x, a, x, elgp, ctx);
		BN_mod_mul (b, b, x, elgp, ctx);
		uint8_t m[255];
		bn2buf (b, m, 255);
		BN_CTX_end (ctx);
		uint8_t hash[32];
		SHA256 (m + 33, 222, hash);
		if (memcmp (m + 1, hash, 32))
		{
			return false;
		}
		memcpy (data, m + 33, 222);
		return true;
	}

	void GenerateElGamalKeyPair (uint8_t * priv, uint8_t * pub)
	{
#if defined(__x86_64__) || defined(__i386__) || defined(_MSC_VER)
		RAND_bytes (priv, 256);
#else
		// lower 226 bits (28 bytes and 2 bits) only. short exponent
		auto numBytes = (ELGAMAL_SHORT_EXPONENT_NUM_BITS)/8 + 1; // 29
		auto numZeroBytes = 256 - numBytes;
		RAND_bytes (priv + numZeroBytes, numBytes);
		memset (priv, 0, numZeroBytes);
		priv[numZeroBytes] &= 0x03;
#endif
		BN_CTX * ctx = BN_CTX_new ();
		BIGNUM * p = BN_new ();
		BN_bin2bn (priv, 256, p);
		BN_mod_exp (p, elgg, p, elgp, ctx);
		bn2buf (p, pub, 256);
		BN_free (p);
		BN_CTX_free (ctx);
	}


	void InitCrypto (bool precomputation)
	{
		i2p::cpu::Detect ();
		SSL_library_init ();
		if (precomputation)
		{
#if defined(__x86_64__)
			g_ElggTable = new BIGNUM * [ELGAMAL_FULL_EXPONENT_NUM_BYTES][255];
			PrecalculateElggTable (g_ElggTable, ELGAMAL_FULL_EXPONENT_NUM_BYTES);
#else
			g_ElggTable = new BIGNUM * [ELGAMAL_SHORT_EXPONENT_NUM_BYTES][255];
			PrecalculateElggTable (g_ElggTable, ELGAMAL_SHORT_EXPONENT_NUM_BYTES);
#endif
		}
	}

	void TerminateCrypto ()
	{
		if (g_ElggTable)
		{
			DestroyElggTable (g_ElggTable,
#if defined(__x86_64__)
				ELGAMAL_FULL_EXPONENT_NUM_BYTES
#else
				ELGAMAL_SHORT_EXPONENT_NUM_BYTES
#endif
			);
			delete[] g_ElggTable; g_ElggTable = nullptr;
		}
/*		CRYPTO_set_locking_callback (nullptr);
		m_OpenSSLMutexes.clear ();*/
	}
}
}
