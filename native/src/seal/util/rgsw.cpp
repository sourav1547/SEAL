/**
	Implementation of Ring-GSW Encryption scheme for its
	application in Oblivious RAM, PIR etc.
*/

#include "seal/randomtostd.h"
#include "seal/util/rlwe.h"
#include "seal/util/common.h"
#include "seal/util/clipnormal.h"
#include "seal/util/polycore.h"
#include "seal/util/smallntt.h"
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/globals.h"
#include "seal/randomgen.h"

using namespace std;

namespace seal
{
	namespace util
	{
		void sample_poly_ternary_rgsw(
			std::shared_ptr<UniformRandomGenerator> rng,
			const RGSWEncryptionParameters &parms, 
			std::uint64_t *destination)
		{
			std::uint64_t kpl = parms.get_rgsw_kpl();
			for (size_t i =0; i < kpl; i+=2)
			{
				util::sample_poly_ternary(rng, parms, destination+i*sizeof(std::uint64_t));
			}
		}

		void sample_poly_normal_rgsw(
			std::shared_ptr<UniformRandomGenerator> rng,
			const RGSWEncryptionParameters &parms, 
			std::uint64_t *destination)
		{
			std::uint64_t kpl = parms.get_rgsw_kpl();
			for (size_t i =0; i < kpl; i+=2)
			{
				util::sample_poly_normal(rng, parms, destination+i*sizeof(std::uint64_t));
			}
		}

		void sample_poly_uniform_rgsw(
			std::shared_ptr<UniformRandomGenerator> rng,
			const RGSWEncryptionParameters &parms, 
			std::uint64_t *destination)
		{
			std::uint64_t kpl = parms.get_rgsw_kpl();
			for (size_t i =0; i < kpl; i+=2)
			{
				util::sample_poly_uniform(rng, parms, destination+i*sizeof(std::uint64_t));
			}	
		}

		void encrypt_zero_asymmetric_rgsw(
			const PublicKey &public_key,
			std::shared_ptr<SEALContext> context,
			parms_id_type parms_id,
			bool is_ntt_form,
			Ciphertext &destination)
		{
			// Using fresh memory
			MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

			auto &context_data = *context->get_context_data(parms_id);
			auto &parms = context_data.parms();
            auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto &small_ntt_tables = context_data.small_ntt_tables();
            size_t encrypted_size = public_key.data().size();

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;

            for (size_t k= 0; k < encrypted_size; k+=2)
            {
            	auto rng = parms.random_generator()->create();

	            // Generate u <-- R_3
	            auto u(allocate_poly(coeff_count, coeff_mod_count, pool));
	            sample_poly_ternary(rng, parms, u.get());

	            // c[j] = u * public_key[j]
	            for (size_t i = 0; i < coeff_mod_count; i++)
	            {
	                ntt_negacyclic_harvey(
	                    u.get() + i * coeff_count,
	                    small_ntt_tables[i]);
	                for (size_t j = 0; j < 2; j++)
	                {
	                    dyadic_product_coeffmod(
	                        u.get() + i * coeff_count,
	                        public_key.data().data(j) + i * coeff_count,
	                        coeff_count,
	                        coeff_modulus[i],
	                        destination.data(k+j) + i * coeff_count);

	                    // addition with e_0, e_1 is in non-NTT form.
	                    if (!is_ntt_form)
	                    {
	                        inverse_ntt_negacyclic_harvey(
	                            destination.data(k+j) + i * coeff_count,
	                            small_ntt_tables[i]);
	                    }
	                }
	            }


	            for (size_t j=0; j < 2; j++){
	            	sample_poly_normal(rng, parms, u.get());

	                for (size_t i = 0; i < coeff_mod_count; i++)
	                {
	                    // addition with e_0, e_1 is in NTT form.
	                    if (is_ntt_form)
	                    {
	                        ntt_negacyclic_harvey(
	                            u.get() + i * coeff_count,
	                            small_ntt_tables[i]);
	                    }
	                    add_poly_poly_coeffmod(
	                        u.get() + i * coeff_count,
	                        destination.data(k+j) + i * coeff_count,
	                        coeff_count,
	                        coeff_modulus[i],
	                        destination.data(k+j) + i * coeff_count);
	                }
	            }
            }
		}

		/*
		Symmetric Key Encryption of Zero in RGSW Scheme.
		*/
        void encrypt_zero_symmetric_rgsw(
            const SecretKey &secret_key,
            std::shared_ptr<SEALContext> context,
            parms_id_type parms_id,
            bool is_ntt_form,
            bool save_seed,
            Ciphertext &destination)
        {	
        	MemoryPoolHandle pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW, true);

        	// We are creating a matrix of containing ciphertexts of zero.
			auto &context_data = *context->get_context_data(parms_id);
			auto &parms = context_data.parms();
			auto &coeff_modulus = parms.coeff_modulus();
            size_t coeff_mod_count = coeff_modulus.size();
            size_t coeff_count = parms.poly_modulus_degree();
            auto &small_ntt_tables = context_data.small_ntt_tables();
			std::uint64_t encrypted_size = parms.get_rgsw_kpl();

			auto poly_uint64_count = mul_safe(coeff_count, coeff_mod_count);            
            if (save_seed &&
                static_cast<uint64_t>(poly_uint64_count) < (random_seed_type().size() + 1))
            {
            	save_seed = false;
            }

            destination.resize(context, parms_id, encrypted_size);
            destination.is_ntt_form() = is_ntt_form;
            destination.scale() = 1.0;


            auto rng_error = parms.random_generator()->create();
            shared_ptr<UniformRandomGenerator> rng_ciphertext;
            rng_ciphertext = BlakePRNGFactory().create();

            // Generate ciphertext as a two dimensional matrix.
            uint64_t *c0, *c1;

			for (size_t i =0; i < encrypted_size; i+=2){
				c0 = destination.data(i);
	            c1 = destination.data(i+1);

	            // Sample a uniformly at random
	            if (is_ntt_form || !save_seed)
	            {
	                // sample the NTT form directly
	                sample_poly_uniform(rng_ciphertext, parms, c1);
	            }
	            else if (save_seed)
	            {
	                // sample non-NTT form and store the seed
	                sample_poly_uniform(rng_ciphertext, parms, c1);
	                for (size_t i = 0; i < coeff_mod_count; i++)
	                {
	                    // Transform the c1 into NTT representation.
	                    ntt_negacyclic_harvey(
	                        c1 + i * coeff_count,
	                        small_ntt_tables[i]);
	                }
	            }

	                        // Sample e <-- chi
            auto noise(allocate_poly(coeff_count, coeff_mod_count, pool));
            sample_poly_normal(rng_error, parms, noise.get());

            // calculate -(a*s + e) (mod q) and store in c[0]
            for (size_t i = 0; i < coeff_mod_count; i++)
            {
                dyadic_product_coeffmod(
                    secret_key.data().data() + i * coeff_count,
                    c1 + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    c0 + i * coeff_count);
                if (is_ntt_form)
                {
                    // Transform the noise e into NTT representation.
                    ntt_negacyclic_harvey(
                        noise.get() + i * coeff_count,
                        small_ntt_tables[i]);
                }
                else
                {
                    inverse_ntt_negacyclic_harvey(
                        c0 + i * coeff_count,
                        small_ntt_tables[i]);
                }
                add_poly_poly_coeffmod(
                    noise.get() + i * coeff_count,
                    c0 + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    c0 + i * coeff_count);
                negate_poly_coeffmod(
                    c0 + i * coeff_count,
                    coeff_count,
                    coeff_modulus[i],
                    c0 + i * coeff_count);
	            }

	            if (!is_ntt_form && !save_seed)
	            {
	                for (size_t i = 0; i < coeff_mod_count; i++)
	                {
	                    // Transform the c1 into non-NTT representation.
	                    inverse_ntt_negacyclic_harvey(
	                        c1 + i * coeff_count,
	                        small_ntt_tables[i]);
	                }
	            }

	            if (save_seed)
	            {
	                random_seed_type seed = rng_ciphertext->seed();
	                // Write random seed to destination.data(1).
	                c1[0] = static_cast<uint64_t>(0xFFFFFFFFFFFFFFFFULL);
	                copy_n(seed.cbegin(), seed.size(), c1 + 1);
	            }	
        	}
        }
	}
}
