/**
This file to test basic implementation of RGSW ciphertexts.
*/


#include "examples.h"

using namespace std;
using namespace seal;

void example_rgsw_basics(){

	/** 
	parms: 
		scheme_type, l, bg_bit 
	*/
	EncryptionParameters parms(scheme_type::RGSW, 4, 2);
	size_t poly_modulus_degree = 1024;
	parms.set_poly_modulus_degree(poly_modulus_degree);

	/**
	Each element in the matrix is still a BFV ciphertext, hence we will
	be able to work of default coefficient modulus for BFV.
	*/
	parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
	parms.set_plain_modulus(27);
	parms.init_gadget_matrix();
	auto context = SEALContext::Create(parms);

	cout << "Encryption parameters set." << endl;
	print_parameters(context);

	KeyGenerator keygen(context);
	PublicKey public_key = keygen.public_key();
	SecretKey secret_key = keygen.secret_key();

	Encryptor encryptor(context, public_key);

	int x = 2;
	Plaintext x_plain(to_string(x));
	cout<< " Plaintext 0x" + x_plain.to_string() <<endl;


	Ciphertext x_encrypted;
	cout<<" Encrypting x_plain."<< endl;
	encryptor.encrypt(x_plain, x_encrypted);
	cout << "    + size of freshly encrypted x: " << x_encrypted.size() << endl;
}
