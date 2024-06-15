//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "mm.hpp"
#include "ext/compact25519/kem.h"
#include <lib/nas/base.hpp>
#include <utils/common.hpp>

// STEPHANE
#include <iostream>
#include <algorithm>

namespace nr::ue
{

void NasMm::receiveIdentityRequest(const nas::IdentityRequest &msg)
{
    nas::IdentityResponse resp;

    if (msg.identityType.value == nas::EIdentityType::SUCI)
    {
        resp.mobileIdentity = getOrGenerateSuci();
    }
    else if (msg.identityType.value == nas::EIdentityType::IMEI)
    {
        resp.mobileIdentity.type = nas::EIdentityType::IMEI;
        resp.mobileIdentity.value = *m_base->config->imei;
    }
    else if (msg.identityType.value == nas::EIdentityType::IMEISV)
    {
        resp.mobileIdentity.type = nas::EIdentityType::IMEISV;
        resp.mobileIdentity.value = *m_base->config->imeiSv;
    }
    else if (msg.identityType.value == nas::EIdentityType::GUTI)
    {
        resp.mobileIdentity = m_storage->storedGuti->get();
    }
    else if (msg.identityType.value == nas::EIdentityType::TMSI)
    {
        // TMSI is already a part of GUTI
        resp.mobileIdentity = m_storage->storedGuti->get();
        if (resp.mobileIdentity.type != nas::EIdentityType::NO_IDENTITY)
        {
            resp.mobileIdentity.type = nas::EIdentityType::TMSI;
            resp.mobileIdentity.gutiOrTmsi.plmn = {};
            resp.mobileIdentity.gutiOrTmsi.amfRegionId = {};
        }
    }
    else
    {
        resp.mobileIdentity.type = nas::EIdentityType::NO_IDENTITY;
        m_logger->err("Requested identity is not available: %d", (int)msg.identityType.value);
    }

    sendNasMessage(resp);
}

nas::IE5gsMobileIdentity NasMm::getOrGenerateSuci()
{
    if (m_timers->t3519.isRunning() && m_storage->storedSuci->get().type != nas::EIdentityType::NO_IDENTITY)
        return m_storage->storedSuci->get();

    m_storage->storedSuci->set(generateSuci());

    m_timers->t3519.start();

    if (m_storage->storedSuci->get().type == nas::EIdentityType::NO_IDENTITY)
        return {};
    return m_storage->storedSuci->get();
}

nas::IE5gsMobileIdentity NasMm::generateSuci()
{
    auto &supi = m_base->config->supi;
    auto &plmn = m_base->config->hplmn;
    auto &protectionScheme = m_base->config->protectionScheme;
    auto &homeNetworkPublicKeyId = m_base->config->homeNetworkPublicKeyId;

    auto &homeNetworkECCPublicKey = m_base->config->homeNetworkECCPublicKey; //ecc

    auto &homeNetworkKyberPublicKey = m_base->config->homeNetworkKyberPublicKey; //kyber

    if (!supi.has_value())
        return {};

    if (supi->type != "imsi")
    {
        m_logger->err("SUCI generating failed, invalid SUPI type: %s", supi->value.c_str());
        return {};
    }

    const std::string &imsi = supi->value;

    nas::IE5gsMobileIdentity ret;
    ret.type = nas::EIdentityType::SUCI;
    ret.supiFormat = nas::ESupiFormat::IMSI;
    ret.imsi.plmn.isLongMnc = plmn.isLongMnc;
    ret.imsi.plmn.mcc = plmn.mcc;
    ret.imsi.plmn.mnc = plmn.mnc;
    if (m_base->config->routingIndicator.has_value())
    {
        ret.imsi.routingIndicator = *m_base->config->routingIndicator;
    }
    else
    {
        ret.imsi.routingIndicator = "0000";
    }
    if (protectionScheme == 0) {
        ret.imsi.protectionSchemaId = 0;
        ret.imsi.homeNetworkPublicKeyIdentifier = 0;
        ret.imsi.schemeOutput = imsi.substr(plmn.isLongMnc ? 6 : 5);
        return ret;
    }
    else if (protectionScheme == 1)
    {
        ret.imsi.protectionSchemaId = 1;
        ret.imsi.homeNetworkPublicKeyIdentifier = homeNetworkPublicKeyId;
        ret.imsi.schemeOutput = generateSUCIProfileA(imsi.substr(plmn.isLongMnc ? 6 : 5), homeNetworkECCPublicKey);
        return ret;
    }
    else if (protectionScheme == 5){ //profile E: Kyber

        ret.imsi.protectionSchemaId = 5;
        ret.imsi.homeNetworkPublicKeyIdentifier = homeNetworkPublicKeyId;

        std::cout<<"\nProtection Scheme: "<<protectionScheme<<std::endl;

        ret.imsi.schemeOutput = generateSUCIProfileE(imsi.substr(plmn.isLongMnc ? 6 : 5), homeNetworkKyberPublicKey);
        return ret;  

    }
    else if (protectionScheme == 6){ //profile F: Kyber + Forward Secrecy (Hybrid PQC)

        ret.imsi.protectionSchemaId = 6;
        ret.imsi.homeNetworkPublicKeyIdentifier = homeNetworkPublicKeyId;

        std::cout<<"\nProtection Scheme: "<<protectionScheme<<std::endl;

        ret.imsi.schemeOutput = generateSUCIProfileF(imsi.substr(plmn.isLongMnc ? 6 : 5),homeNetworkECCPublicKey, homeNetworkKyberPublicKey);
        return ret;  

    }
    else
    {
        m_logger->err("Protection Scheme %d not implemented", protectionScheme);
        return {};
    }
}

Random returnSeed(std::string name){ 

    Random rnd = Random::Mixed(name);
    return rnd;

}

void x25519Common(uint8_t *privateKey, uint8_t * publicKey){

    /* Generates the key  & fills in the values*/

    std::string name("Seed for x25519 generation");
    std::string seed;

    Random rnd = returnSeed(name);
    int intLength = sizeof(int32_t);

    for (int i=0; i < (X25519_KEY_SIZE/intLength); i++)
    {
        seed = seed + utils::IntToHex(rnd.nextI());
    }

    // getting a random seed & then ephemeral key gen. seed -> priv key

    OctetString randomSeed = OctetString::FromHex(seed); 
    compact_x25519_keygen(privateKey,publicKey, randomSeed.data());
    return;


}

std::string NasMm::generateSUCIProfileA(const std::string &imsi, const OctetString &hnPublicKey)
{

    uint8_t privateKey[X25519_KEY_SIZE];
    uint8_t publicKey[X25519_KEY_SIZE];   

    x25519Common(privateKey,publicKey);

    OctetString shared;
    shared.appendPadding(32);

    OctetString uePrivateKey = OctetString::FromArray(privateKey,X25519_KEY_SIZE);
    OctetString uePublicKey = OctetString::FromArray(publicKey,X25519_KEY_SIZE);

    compact_x25519_shared(shared.data(),privateKey,hnPublicKey.data());

    //KDF 
    uint8_t derivatedKey[64];
    x963kdf(derivatedKey, shared.data(), uePublicKey.data(), 64,X25519_SHARED_SIZE,X25519_KEY_SIZE);
    OctetString buf = OctetString::FromArray(derivatedKey, 64);
    OctetString encryptionKey = buf.subCopy(0, 16);
    OctetString initializationVector = buf.subCopy(16, 16);
    OctetString macKey = buf.subCopy(32, 32);

    //encrypt msin.
    OctetString msin;
    nas::EncodeBcdString(msin, imsi, ~0, false, 0);
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, encryptionKey.data());
    AES_ctx_set_iv(&ctx, initializationVector.data());
    AES_CTR_xcrypt_buffer(&ctx, msin.data(), msin.length());

    // calculate HMAC
    uint8_t suciHMAC[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(suciHMAC, msin.data(), msin.length(), macKey.data(), HMAC_SHA256_DIGEST_SIZE);
    
    //append the ciphered msin (cipherText) & the Mac tag to the final concealed secret.
    OctetString macTag = OctetString::FromArray(suciHMAC, 8);
    OctetString schemeOutput;
    schemeOutput.append(uePublicKey);
    schemeOutput.append(msin);
    schemeOutput.append(macTag);
    return schemeOutput.toHexString();
}

nas::IE5gsMobileIdentity NasMm::getOrGeneratePreferredId()
{
    if (m_storage->storedGuti->get().type != nas::EIdentityType::NO_IDENTITY)
        return m_storage->storedGuti->get();

    auto suci = getOrGenerateSuci();
    if (suci.type != nas::EIdentityType::NO_IDENTITY)
    {
        return suci;
    }
    else if (m_base->config->imei.has_value())
    {
        nas::IE5gsMobileIdentity res{};
        res.type = nas::EIdentityType::IMEI;
        res.value = *m_base->config->imei;
        return res;
    }
    else if (m_base->config->imeiSv.has_value())
    {
        nas::IE5gsMobileIdentity res{};
        res.type = nas::EIdentityType::IMEISV;
        res.value = *m_base->config->imeiSv;
        return res;
    }
    else
    {
        nas::IE5gsMobileIdentity res{};
        res.type = nas::EIdentityType::NO_IDENTITY;
        return res;
    }
}

/* Kyber */

std::string NasMm::generateSUCIProfileE(const std::string &imsi, const OctetString &hnKyberPublicKey){

    uint8_t sharedSecret[KYBER_CIPHER_SIZE];
    uint8_t cipherText[KYBER_CIPHER_SIZE];

    key_encaps(hnKyberPublicKey.data(),sharedSecret,cipherText); //we obtain a SS & a CipherText. This SS is used for deriving an enc key.

    //KDF 

    OctetString shared = OctetString::FromArray(sharedSecret,KYBER_SHARED_SIZE); //first create an Octet string from the uint8 array.

    const size_t keySize = 80;
    uint8_t derivatedKey[keySize];

    x963kdf(derivatedKey, sharedSecret, hnKyberPublicKey.data(), keySize,KYBER_SHARED_SIZE,KYBER_PUBLIC_SIZE); //returns a x bytes key, we will divide it into: Enc key, IV & Mac

    OctetString buf = OctetString::FromArray(derivatedKey, keySize);
    
    OctetString encryptionKey = buf.subCopy(0, 32); //encryption key: 32 bytes.
    OctetString initializationVector = buf.subCopy(32, 16);

    OctetString macKey = buf.subCopy(48, 32); //mac key: 32 bytes, from this we will compute a macTag.
 
    // encrypt msin
    OctetString msin;
    nas::EncodeBcdString(msin, imsi, ~0, false, 0);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, encryptionKey.data());
    AES_ctx_set_iv(&ctx, initializationVector.data());
    AES_CTR_xcrypt_buffer(&ctx, msin.data(), msin.length());

    // calculate HMAC
    uint8_t suciHMAC[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(suciHMAC, msin.data(), msin.length(), macKey.data(), HMAC_SHA256_DIGEST_SIZE);

    //mac tag: just 8 bytes.
    OctetString macTag = OctetString::FromArray(suciHMAC, 8);

    OctetString schemeOutput;
    OctetString cipherText_2 = OctetString::FromArray(cipherText,768);

    std::cout<<"\nCipher text: "<<cipherText_2.toHexString()<<std::endl;
    std::cout<<"\nshared secret: "<<std::hex <<shared.toHexString()<<std::endl;
    std::cout<<"\nEnc key: "<<std::hex <<encryptionKey.toHexString()<<std::endl;
    std::cout<<"\nMac key: "<<std::hex <<macKey.toHexString()<<std::endl;
    std::cout<<"\nMac tag: "<<std::hex <<macTag.toHexString()<<std::endl;



    schemeOutput.append(cipherText_2); // 768 bytes of cipher text + encrypted msin + mac tag.
    schemeOutput.append(msin);
    schemeOutput.append(macTag);

    return schemeOutput.toHexString();

}

/* Kyber + ECDH (Hybrid PQC)*/

std::string NasMm::generateSUCIProfileF(const std::string &imsi, const OctetString &hnECCPublicKey , const OctetString &hnKyberPublicKey){


    /* ECDH */
    uint8_t eccPrivateKey[X25519_KEY_SIZE];
    uint8_t eccPublicKey[X25519_KEY_SIZE];   

    x25519Common(eccPrivateKey,eccPublicKey);

    OctetString sharedECC;
    sharedECC.appendPadding(32);

    OctetString ephPrivateKey = OctetString::FromArray(eccPrivateKey,X25519_KEY_SIZE);
    OctetString ephPublicKey = OctetString::FromArray(eccPublicKey,X25519_KEY_SIZE);

    std::cout<<"Ephemeral Keys (Eph pub & HN pub): "<<std::endl;
    std::cout <<"Eph pub: "<< ephPublicKey.toHexString()<<std::endl;
    std::cout <<"Hn Pub: "<<hnECCPublicKey.toHexString()<<std::endl;
    std::cout <<"Eph Private Key: "<<ephPrivateKey.toHexString()<<std::endl;

    compact_x25519_shared(sharedECC.data(),eccPrivateKey,hnECCPublicKey.data());

    /* Kyber KEM*/

    uint8_t sharedKyber[KYBER_SHARED_SIZE]; //32 bytes shared Secret
    uint8_t cipherText[KYBER_CIPHER_SIZE];

    key_encaps(hnKyberPublicKey.data(),sharedKyber,cipherText); //we obtain a SS & a CipherText. This SS is used for deriving an enc key.

    //KDF 

    // concatenate 2 shared secrets into 1 . Order:  ECDH + KyberKem
    uint8_t sharedSecret[X25519_SHARED_SIZE + KYBER_CIPHER_SIZE];

    std::copy(sharedECC.data(), sharedECC.data() + X25519_KEY_SIZE, sharedSecret);
    std::copy(sharedKyber, sharedKyber + KYBER_CIPHER_SIZE, sharedSecret + X25519_SHARED_SIZE);

    OctetString shared = OctetString::FromArray(sharedSecret,64); //first create an Octet string from the uint8 array.

    const size_t keySize = 80;

    uint8_t derivatedKey[keySize];
    x963kdf(derivatedKey, sharedSecret, hnECCPublicKey.data(), keySize,X25519_SHARED_SIZE + KYBER_SHARED_SIZE,X25519_KEY_SIZE); //returns a x bytes key, we will divide it into: Enc key, IV & Mac

    OctetString buf = OctetString::FromArray(derivatedKey, keySize);
    
    OctetString encryptionKey = buf.subCopy(0, 32); //encryption key: 32 bytes.
    OctetString initializationVector = buf.subCopy(32, 16);

    OctetString macKey = buf.subCopy(48, 32); //mac key: 32 bytes, from this we will compute a macTag.
 
    // encrypt msin
    OctetString msin;
    nas::EncodeBcdString(msin, imsi, ~0, false, 0);

    struct AES_ctx ctx;
    AES_init_ctx(&ctx, encryptionKey.data());
    AES_ctx_set_iv(&ctx, initializationVector.data());
    AES_CTR_xcrypt_buffer(&ctx, msin.data(), msin.length());

    // calculate HMAC
    uint8_t suciHMAC[HMAC_SHA256_DIGEST_SIZE];
    hmac_sha256(suciHMAC, msin.data(), msin.length(), macKey.data(), HMAC_SHA256_DIGEST_SIZE);

    //mac tag: just 8 bytes.
    OctetString macTag = OctetString::FromArray(suciHMAC, 8);

    OctetString schemeOutput;

    OctetString cipherText_2 = OctetString::FromArray(cipherText,768);
    OctetString sharedKyber_ = OctetString::FromArray(sharedKyber,32);

    // std::cout<<"HN ECC pub key: "<<hnECCPublicKey.toHexString()<<std::endl;
    std::cout<<"\nCipher text: "<<cipherText_2.toHexString()<<std::endl;
    // std::cout<<"\n MSIN encrypted: "<<std::hex <<msin.toHexString()<<std::endl;
    std::cout<<"\nECC shared secret: "<<std::hex <<sharedECC.toHexString()<<std::endl;
    std::cout<<"\nKyber shared secret: "<<std::hex <<sharedKyber_.toHexString()<<std::endl;
    std::cout<<"\nshared secret: "<<std::hex <<shared.toHexString()<<std::endl;
    std::cout<<"\nEnc key: "<<std::hex <<encryptionKey.toHexString()<<std::endl;
    std::cout<<"\nMac key: "<<std::hex <<macKey.toHexString()<<std::endl;
    std::cout<<"\nMac tag: "<<std::hex <<macTag.toHexString()<<std::endl;



    schemeOutput.append(ephPublicKey);
    schemeOutput.append(cipherText_2); // 768 bytes of cipher text + encrypted msin + mac tag.
    schemeOutput.append(msin);
    schemeOutput.append(macTag);

    return schemeOutput.toHexString();


}


} // namespace nr::ue

