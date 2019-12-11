/**
	Implementation of Ring-GSW Encryption scheme for its
	application in Oblivious RAM, PIR etc.
*/

#pragma once


#include <cstdint>
#include "seal/randomgen.h"
#include "seal/encryptionparams.h"
#include "seal/publickey.h"
#include "seal/secretkey.h"
#include "seal/publickey.h"
#include "seal/ciphertext.h"
#include "seal/context.h"

namespace seal
{
	namespace util
	{
		/**
		Generate a array of ternary polynomial uniformly and store each polynomial in RNS representation.

		@parm[in] rng A uniform random generator.
		@parm[in] parms EncryptionParameters used to parmeterize an RNS polynomial
		@parm[in] rgsw_sise Size of the Ring-GSW ciphertext
		@parm[out] destination Allocated space to store the entire rgsw ciphertext
		*/
		void sample_poly_ternary_rgsw(
			std::shared_ptr<UniformRandomGenerator> rng,
			const RGSWEncryptionParameters &parms, 
			std::uint64_t *destination);

		/**
		Generate a array of polynomial from a normal distribution and store each polynomial in RNS representation.

		@parm[in] rng A uniform random generator.
		@parm[in] parms EncryptionParameters used to parmeterize an RNS polynomial
		@parm[in] rgsw_sise Size of the Ring-GSW ciphertext
		@parm[out] destination Allocated space to store the entire rgsw ciphertext
		*/
		void sample_poly_normal_rgsw(
			std::shared_ptr<UniformRandomGenerator> rng,
			const RGSWEncryptionParameters &parms, 
			std::uint64_t *destination);

		/**
		Generate a array of polynomial uniformly from Rq and store each polynomial in RNS representation.

		@parm[in] rng A uniform random generator.
		@parm[in] parms EncryptionParameters used to parmeterize an RNS polynomial
		@parm[in] rgsw_sise Size of the Ring-GSW ciphertext
		@parm[out] destination Allocated space to store the entire rgsw ciphertext
		*/
		void sample_poly_uniform_rgsw(
			std::shared_ptr<UniformRandomGenerator> rng,
			const RGSWEncryptionParameters &parms, 
			const int rgsw_size,
			std::uint64_t *destination);


		/**
		Create an encryption of zero with a secret key and store 
		it in a cipher text.

        @parm[in] public_key The public key used for encryption.
        @parm[in] context The SEALContext containing a chain of ContextData.
        @parm[in] parms_id Indicates the level of encryption.
        @parm[in] is_ntt_form If true, store Ciphertext in NTT form.
        @parm[out] destination The output ciphertext - an encryption of zero.

        @sourav: I am assuming that the context will have size of the array.
		*/
		void encrypt_zero_asymmetric_rgsw(
			const PublicKey &public_key,
			std::shared_ptr<SEALContext> context,
			parms_id_type parms_id,
			bool is_ntt_form,
			Ciphertext &destination);


		/**
        Create an encryption of zero with a secret key and store in a ciphertext.

        @parm[out] destination The output ciphertext - an encryption of zero.
        @parm[in] secret_key The secret key used for encryption.
        @parm[in] context The SEALContext containing a chain of ContextData.
        @parm[in] parms_id Indicates the level of encryption.
        @parm[in] is_ntt_form If true, store Ciphertext in NTT form.
        @parm[in] save_seed If true, The second component of ciphertext is
        replaced with the random seed used to sample this component.
        */
        void encrypt_zero_symmetric_rgsw(
            const SecretKey &secret_key,
            std::shared_ptr<SEALContext> context,
            parms_id_type parms_id,
            bool is_ntt_form,
            bool save_seed,
            Ciphertext &destination);


		/**
        Perform an external produce between a Ring-GSW ciphertext and Ring-LWE ciphertext.

        @parm[in] context The SEALContext containing a chain of ContextData.
        @parm[in] parms_id Indicates the level of encryption.
        @parm[in] is_ntt_form If true, store Ciphertext in NTT form.
        @parm[in] save_seed If true, The second component of ciphertext is replaced with the random seed used to sample this component.
        @parm[in] rgsw_ct Ring-GSW ciphertext
        @parm[in] rlwe_ct Ring-LWE ciphertext

        @parm[out] destination The output of the external product
        */
        void external_prod(
        	std::shared_ptr<SEALContext> context,
        	parms_id_type parms,
        	bool is_ntt_form,
        	bool save_seed,
        	Ciphertext &rgsw_ct,
        	Ciphertext &rlwe_ct,
        	Ciphertext &destination);

	}
}
