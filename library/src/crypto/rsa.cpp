#include "crypto/rsa.h"
#include "config.h"
#include "misc.h"
#include <string.h>
#include <memory>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <stdexcept>
#include <iostream>

using namespace Dnp;

Rsa::Rsa()
{
}

Rsa::~Rsa()
{
}

void Rsa::decrypt_public(const std::string &pub_key, const std::string &input, std::string &out)
{
    // Reset out to nothing
    out = "";

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;
    EVP_PKEY *evp_pbkey = NULL;
    EVP_PKEY *evp_pkey = NULL;

    BIO *pkeybio = NULL;
    pkeybio = BIO_new_mem_buf((void *)pub_key.c_str(), pub_key.size());
    if (pkeybio == NULL)
    {
        throw std::logic_error("decrypt_public(): Problem allocating buffer");
    }

    p_rsa = PEM_read_bio_RSAPublicKey(pkeybio, &p_rsa, NULL, NULL);
    if (p_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        throw std::logic_error("decrypt_public(): " + std::string(buffer, sizeof(buffer)));
    }

    std::unique_ptr<char[]> decrypted = std::make_unique<char[]>(RSA_size(p_rsa));
    memset(decrypted.get(), 0, RSA_size(p_rsa));

    int decrypt_len;
    if ((decrypt_len = RSA_public_decrypt(input.size(), (unsigned char *)input.c_str(),
                                          (unsigned char *)decrypted.get(), p_rsa, RSA_PKCS1_PADDING)) == -1)
    {
        throw std::logic_error("decrypt_public(): problem encrypting with private key");
    }

    out = std::string(decrypted.get(), decrypt_len);
    BIO_free(pkeybio);
}

void Rsa::encrypt_private(const std::string &pri_key, const std::string &input, std::string &out)
{
    // Reset out to nothing
    out = "";

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;
    EVP_PKEY *evp_pbkey = NULL;
    EVP_PKEY *evp_pkey = NULL;

    BIO *pkeybio = NULL;
    pkeybio = BIO_new_mem_buf((void *)pri_key.c_str(), pri_key.size());
    if (pkeybio == NULL)
    {
        throw std::logic_error("encrypt_private(): Problem allocating buffer");
    }

    p_rsa = PEM_read_bio_RSAPrivateKey(pkeybio, &p_rsa, NULL, NULL);
    if (p_rsa == NULL)
    {
        char buffer[120];
        ERR_error_string(ERR_get_error(), buffer);
        throw std::logic_error("encrypt_private(): " + std::string(buffer, sizeof(buffer)));
    }

    std::unique_ptr<char[]> encrypt = std::make_unique<char[]>(RSA_size(p_rsa));
    memset(encrypt.get(), 0, RSA_size(p_rsa));

    int encrypt_len;
    if ((encrypt_len = RSA_private_encrypt(input.size(), (unsigned char *)input.c_str(),
                                           (unsigned char *)encrypt.get(), p_rsa, RSA_PKCS1_PADDING)) == -1)
    {
        throw std::logic_error("encrypt_private(): problem encrypting with private key");
    }

    out = std::string(encrypt.get(), RSA_size(p_rsa));
    BIO_free(pkeybio);
}

std::string Rsa::makeEncryptedHash(const std::string &input, const std::string &private_key)
{
    std::string data_hash = md5_hex(input);
    std::string encrypted_data_hash = "";
    Rsa::encrypt_private(private_key, data_hash, encrypted_data_hash);
    return encrypted_data_hash;
}

std::string Rsa::makeEncryptedHash(const std::string& input, const std::string& private_key, struct DnpEncryptedHash& out_hash)
{
    std::string result = makeEncryptedHash(input, private_key);
    if(result.size() > sizeof(out_hash.hash))
        throw std::logic_error("Problem the hash generated is bigger than it can hold attempting to copy would cause program crash");
    memcpy(out_hash.hash, result.c_str(), result.size());
    out_hash.size = result.size();
    return result;
}

struct rsa_keypair Rsa::generateKeypair()
{

    RSA *keypair = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;

    unsigned long e = RSA_F4;

    BIGNUM *bne = BN_new();
    int ret = BN_set_word(bne, e);
    if (ret != 1)
    {
        throw std::logic_error("Problem generating BN");
    }

    keypair = RSA_new();

    ret = RSA_generate_key_ex(keypair, RSA_BITS, bne, NULL);

    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    std::unique_ptr<char[]> pri_key(new char[pri_len]);
    std::unique_ptr<char[]> pub_key(new char[pub_len]);

    BIO_read(pri, pri_key.get(), pri_len);
    BIO_read(pub, pub_key.get(), pub_len);

    struct rsa_keypair rsa_keypair;
    rsa_keypair.pub_key = std::string(pub_key.get(), pub_len);
    rsa_keypair.private_key = std::string(pri_key.get(), pri_len);
    rsa_keypair.private_key_md5_hash = md5_hex(rsa_keypair.private_key);
    rsa_keypair.pub_key_md5_hash = md5_hex(rsa_keypair.pub_key);

    return rsa_keypair;
}