/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pk_keys.h>
#include <botan/pk_ops.h>
#include <botan/der_enc.h>
#include <botan/oids.h>

namespace Botan {

/*
* Default OID access
*/
OID Public_Key::get_oid() const
   {
   try {
      return OIDS::lookup(algo_name());
      }
   catch(Lookup_Error&)
      {
      throw Lookup_Error("PK algo " + algo_name() + " has no defined OIDs");
      }
   }

/*
* Run checks on a loaded public key
*/
void Public_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD))
      throw Invalid_Argument("Invalid public key");
   }

/*
* Run checks on a loaded private key
*/
void Private_Key::load_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD))
      throw Invalid_Argument("Invalid private key");
   }

/*
* Run checks on a generated private key
*/
void Private_Key::gen_check(RandomNumberGenerator& rng) const
   {
   if(!check_key(rng, BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE))
      throw Self_Test_Failure("Private key generation failed");
   }

std::unique_ptr<PK_Ops::Encryption>
Public_Key::create_encryption_op(RandomNumberGenerator& /*rng*/,
                                 const std::string& /*params*/,
                                 const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support encryption");
   }

std::unique_ptr<PK_Ops::KEM_Encryption>
Public_Key::create_kem_encryption_op(RandomNumberGenerator& /*rng*/,
                                     const std::string& /*params*/,
                                     const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM encryption");
   }

std::unique_ptr<PK_Ops::Verification>
Public_Key::create_verification_op(RandomNumberGenerator& /*rng*/,
                                   const std::string& /*params*/,
                                   const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support verification");
   }

std::unique_ptr<PK_Ops::Decryption>
Private_Key::create_decryption_op(RandomNumberGenerator& /*rng*/,
                                  const std::string& /*params*/,
                                  const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support decryption");
   }

std::unique_ptr<PK_Ops::KEM_Decryption>
Private_Key::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
                                      const std::string& /*params*/,
                                      const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support KEM decryption");
   }

std::unique_ptr<PK_Ops::Signature>
Private_Key::create_signature_op(RandomNumberGenerator& /*rng*/,
                                 const std::string& /*params*/,
                                 const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support signatures");
   }

std::unique_ptr<PK_Ops::Key_Agreement>
Private_Key::create_key_agreement_op(RandomNumberGenerator& /*rng*/,
                                     const std::string& /*params*/,
                                     const std::string& /*provider*/) const
   {
   throw Lookup_Error(algo_name() + " does not support key agreement");
   }

}
