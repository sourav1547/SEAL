/**
    Implements the parameter file of RGSW Encryption
*/
#pragma once

#include <iostream>
#include <numeric>
#include <memory>
#include <functional>
#include "seal/util/defines.h"
#include "seal/util/globals.h"
#include "seal/randomgen.h"
#include "seal/smallmodulus.h"
#include "seal/util/hash.h"
#include "seal/memorymanager.h"
#include "seal/serialization.h"
#include "seal/util/ztools.h"

namespace seal
{
    class RGSWEncryptionParameters: public EncryptionParameters
    {
        friend class SEALContext;
        
    public:   

        /**
        Returns an upper bound on the size of the EncryptionParameters, as if it
        was written to an output stream.

        @parm[in] compr_mode The compression mode
        @throws std::invalid_argument if the compression mode is not supported
        @throws std::logic_error if the size does not fit in the return type
        */
        SEAL_NODISCARD inline std::streamoff save_size(
            compr_mode_type compr_mode) const
        {
            std::size_t coeff_modulus_total_size = coeff_modulus_.empty() ?
                std::size_t(0) :
                util::safe_cast<std::size_t>(
                    coeff_modulus_[0].save_size(compr_mode_type::none));
            coeff_modulus_total_size = util::mul_safe(
                coeff_modulus_total_size, coeff_modulus_.size());

            std::size_t members_size = Serialization::ComprSizeEstimate(
                util::add_safe(
                    sizeof(scheme_),
                    sizeof(std::uint64_t), // poly_modulus_degree_
                    sizeof(std::uint64_t), // coeff_mod_count

                    //RGSW Additional parameters.
                    sizeof(std::uint64_t), // bg_
                    sizeof(std::uint64_t), // half_bg_
                    sizeof(std::uint64_t), // l_, number of rows
                    sizeof(std::uint64_t), // bg_bit_, size of base
                    sizeof(std::uint64_t), // mask_mod_ 
                    sizeof(std::uint64_t),  // kpl_

                    coeff_modulus_total_size,
                    util::safe_cast<std::size_t>(
                        plain_modulus_.save_size(compr_mode_type::none))),


                compr_mode);

            return util::safe_cast<std::streamoff>(util::add_safe(
                sizeof(Serialization::SEALHeader),
                members_size
            ));
        }
    
    private:
        scheme_type scheme_;
        // RGSW parameters, I am currently defining them to be 
        // 64 bit integers. We can later change them as per the need. 
        std::uint64_t l_ = 1;  //decomposition length
        std::uint64_t bg_bit_ = 1; // log_2(Bg)
        std::uint64_t bg_ = 2;// Decomposition base
        std::uint64_t half_bg_ = 1; // Bg/2
        std::uint64_t mask_mod_; // Bg-1 Todo:Check whether this is necessary
        std::uint64_t kpl_; // number of rows (k+1)*l. In the RGSW example shown in Ring-ORAM k=1.

    };
}
