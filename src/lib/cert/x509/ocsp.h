/*
* OCSP
* (C) 2012 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_OCSP_H__
#define BOTAN_OCSP_H__

#include <botan/cert_status.h>
#include <botan/ocsp_types.h>

namespace Botan {

class Certificate_Store;

namespace OCSP {

class BOTAN_DLL Request
   {
   public:
      Request(const X509_Certificate& issuer_cert,
              const X509_Certificate& subject_cert) :
         m_issuer(issuer_cert),
         m_subject(subject_cert)
         {}

      std::vector<byte> BER_encode() const;

      std::string base64_encode() const;

      const X509_Certificate& issuer() const { return m_issuer; }

      const X509_Certificate& subject() const { return m_subject; }
   private:
      X509_Certificate m_issuer, m_subject;
   };

class BOTAN_DLL Response
   {
   public:
      Response() {}

      Response(const std::vector<byte>& response);

      // Throws if validation failed
      void check_signature(const Certificate_Store& trust_roots);

      const X509_Time& produced_at() const { return m_produced_at; }

      Certificate_Status_Code status_for(const X509_Certificate& issuer,
                                               const X509_Certificate& subject) const;

   private:
      X509_Time m_produced_at;
      X509_DN m_signer_name;
      std::vector<byte> m_tbs_bits;
      AlgorithmIdentifier m_sig_algo;
      std::vector<byte> m_signature;
      std::vector<X509_Certificate> m_certs;

      std::vector<SingleResponse> m_responses;
   };

BOTAN_DLL Response online_check(const X509_Certificate& issuer,
                                const X509_Certificate& subject,
                                const Certificate_Store* trusted_roots);

}

}

#endif
