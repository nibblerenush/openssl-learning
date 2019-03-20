#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

std::string GetSslInfo()
{
  std::ostringstream ostringstream;
  ostringstream
    << SSLeay_version(SSLEAY_VERSION) << '\n'
    << SSLeay_version(SSLEAY_CFLAGS) << '\n'
    << SSLeay_version(SSLEAY_BUILT_ON) << '\n'
    << SSLeay_version(SSLEAY_PLATFORM) << '\n'
    << SSLeay_version(SSLEAY_DIR )<< '\n';
  return ostringstream.str();
}

std::string GetSslErrorString()
{
  std::ostringstream ostringstream;
  ostringstream
    << ERR_error_string(ERR_get_error(), nullptr) << '\n'
    << ERR_lib_error_string(ERR_get_error()) << '\n'
    << ERR_func_error_string(ERR_get_error()) << '\n'
    << ERR_reason_error_string(ERR_get_error());
  return ostringstream.str();
}

std::string GetOsErrorString()
{
  std::ostringstream ostringstream;
  ostringstream << std::strerror(errno);
  return ostringstream.str();
}

void GetFileData(std::unique_ptr<unsigned char[]> & data, std::size_t & size, const char * fileName)
{
  std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(fileName, "rb"), &std::fclose);
  if (!file)
  {
    throw std::runtime_error(GetOsErrorString());
  }
  
  if (std::fseek(file.get(), 0, SEEK_END) == -1)
  {
    throw std::runtime_error(GetOsErrorString());
  }
  size = std::ftell(file.get());
  if (size == -1)
  {
    throw std::runtime_error(GetOsErrorString());
  }
  if (std::fseek(file.get(), 0, SEEK_SET) == -1)
  {
    throw std::runtime_error(GetOsErrorString());
  }
  
  data = std::unique_ptr<unsigned char[]>(new unsigned char [size]);
  if (std::fread( data.get(), size, 1, file.get()) == 0)
  {
    throw std::runtime_error(GetOsErrorString());
  }
}

void GenerateRsaAndWritePem()
{
  try
  {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), &EVP_PKEY_free);
    if (!pkey)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    BIGNUM * bignum = BN_new();
    if (!bignum)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    if (!BN_set_word(bignum, RSA_F4))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    RSA * rsa = RSA_new();
    if (!rsa)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    if (!RSA_generate_key_ex(rsa, 2048, bignum, nullptr))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    if (!EVP_PKEY_assign_RSA(pkey.get(), rsa))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
    {
      std::cout << "This is RSA" << std::endl;
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFilePublicKey(fopen("public_key.pem", "wb"), &std::fclose);
    if (!pemFilePublicKey)
    {
      throw std::runtime_error(GetOsErrorString());
    }
    if (!PEM_write_PUBKEY(pemFilePublicKey.get(), pkey.get()))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFileRsaPublicKey(fopen("rsa_public_key.pem", "wb"), &std::fclose);
    if (!pemFileRsaPublicKey)
    {
      throw std::runtime_error(GetOsErrorString());
    }
    if (!PEM_write_RSA_PUBKEY(pemFileRsaPublicKey.get(), rsa))
    {
      throw std::runtime_error(GetOsErrorString());
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFilePrivateKey(fopen("private_key.pem", "wb"), &std::fclose);
    if (!pemFilePrivateKey)
    {
      throw std::runtime_error(GetOsErrorString());
    }
    if (!PEM_write_PrivateKey(pemFilePrivateKey.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFileRsaPrivateKey(fopen("rsa_private_key.pem", "wb"), &std::fclose);
    if (!pemFileRsaPrivateKey)
    {
      throw std::runtime_error(GetOsErrorString());
    }
    if (!PEM_write_RSAPrivateKey(pemFileRsaPrivateKey.get(), rsa, nullptr, nullptr, 0, nullptr, nullptr))
    {
      throw std::runtime_error(GetSslErrorString());
    }
  }
  catch(std::runtime_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
}

void GetEncryptedText(std::unique_ptr<unsigned char[]> & inText, std::size_t & inSize)
{
  GetFileData(inText, inSize, "encrypted_text.bin");
}

void ReadPemAndDecryptMessage()
{
  try
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFilePrivateKey(std::fopen("private_key.pem", "rb"), &std::fclose);
    if (!pemFilePrivateKey)
    {
      throw std::runtime_error(GetOsErrorString());
    }
    EVP_PKEY * rawPkey;
    if (!PEM_read_PrivateKey(pemFilePrivateKey.get(), &rawPkey, nullptr, nullptr))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(rawPkey, &EVP_PKEY_free);
    
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
    {
      std::cout << "This is RSA" << std::endl;
    }
    
    std::size_t inSize;
    std::unique_ptr<unsigned char[]> inText;
    GetEncryptedText(inText, inSize);
    
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pkeyContext(EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!pkeyContext)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    if (EVP_PKEY_decrypt_init(pkeyContext.get()) <= 0)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::size_t outSize;
    if (EVP_PKEY_decrypt(pkeyContext.get(), nullptr, &outSize, inText.get(), inSize) <= 0)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::unique_ptr<unsigned char[]> outText(new unsigned char [outSize]);
    if (EVP_PKEY_decrypt(pkeyContext.get(), outText.get(), &outSize, inText.get(), inSize) <= 0)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::cout << "out: " << (char*)outText.get() << std::endl;
  }
  catch(std::runtime_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
}

void GetVerifyingMessage(std::unique_ptr<unsigned char[]> & messageText, std::size_t & messageSize)
{
  GetFileData(messageText, messageSize, "message.txt");
}

void GetSignature(std::unique_ptr<unsigned char[]> & signatureText, std::size_t & signatureSize)
{
  GetFileData(signatureText, signatureSize, "signature.bin");
}

void ReadPemAndVerifyMessage()
{
  try
  {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)> mdContext(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    if (!mdContext)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFilePublicKey(std::fopen("public_key.pem", "rb"), &std::fclose);
    if (!pemFilePublicKey)
    {
      throw std::runtime_error(GetOsErrorString());
    }
    EVP_PKEY * rawPkey;
    if (!PEM_read_PUBKEY(pemFilePublicKey.get(), &rawPkey, nullptr, nullptr))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(rawPkey, &EVP_PKEY_free);
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA)
    {
      std::cout << "This is RSA" << std::endl;
    }
    
    if (EVP_DigestVerifyInit(mdContext.get(), nullptr, EVP_sha256(), nullptr, pkey.get()) <= 0)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::size_t messageSize;
    std::unique_ptr<unsigned char[]> messageText;
    GetVerifyingMessage(messageText, messageSize);
    if (EVP_DigestVerifyUpdate(mdContext.get(), messageText.get(), messageSize) <= 0)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::size_t signatureSize;
    std::unique_ptr<unsigned char[]> signatureText;
    GetSignature(signatureText, signatureSize);
    if (EVP_DigestVerifyFinal(mdContext.get(), signatureText.get(), signatureSize))
    {
      std::cout << "Verifying SUCCESS" << std::endl;
    }
    else
    {
      std::cout << "Verifying FAILURE" << std::endl;
    }
  }
  catch (std::runtime_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
}

void GetSignatureWithoutDigest(std::unique_ptr<unsigned char[]> & signatureText, std::size_t & signatureSize)
{
  GetFileData(signatureText, signatureSize, "rsautl_signature.bin");
}

void ReadPemAndVerifyMessageWithoutDigest()
{
  try
  {
    BIO * pemFilePublicKey = BIO_new_file("public_key.pem", "rb");
    if (!pemFilePublicKey)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    EVP_PKEY * rawPkey;
    EVP_PKEY * returnPkey = PEM_read_bio_PUBKEY(pemFilePublicKey, &rawPkey, nullptr, nullptr);
    if (!returnPkey)
    {
      throw std::runtime_error(GetSslErrorString());      
    }
    if (EVP_PKEY_type(rawPkey->type) == EVP_PKEY_RSA)
    {
      std::cout << "This is RSA" << std::endl;
    }
    
    std::size_t messageSize;
    std::unique_ptr<unsigned char[]> messageText;
    GetVerifyingMessage(messageText, messageSize);
    
    std::size_t signatureSize;
    std::unique_ptr<unsigned char[]> signatureText;
    GetSignatureWithoutDigest(signatureText, signatureSize);
    
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> pkeyContext(EVP_PKEY_CTX_new(rawPkey, nullptr), &EVP_PKEY_CTX_free);
    if (!pkeyContext)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    if (EVP_PKEY_verify_init(pkeyContext.get()) <= 0)
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    if (EVP_PKEY_verify(pkeyContext.get(), signatureText.get(), signatureSize, messageText.get(), messageSize))
    {
      std::cout << "Verifying SUCCESS" << std::endl;
    }
    else
    {
      std::cout << "Verifying FAILURE" << std::endl;
    }
    
    EVP_PKEY_free(rawPkey);
    BIO_free_all(pemFilePublicKey);
  }
  catch (std::runtime_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
}

int main(int argc, char ** argv)
{
  if (argc != 2)
  {
    std::cerr << "Usage: openssl-learning [operation]" << std::endl;
    return EXIT_FAILURE;
  }
  
  std::cout << GetSslInfo() << std::endl;
  std::cout << "openssl_learning: start" << std::endl;
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  int operation = std::atoi(argv[1]);
  switch (operation)
  {
    case 1:
      /* in:
       * out: */
      GenerateRsaAndWritePem();
      break;
    case 2:
      /* in: openssl pkeyutl -encrypt -inkey ./public_key.pem -pubin -out ./encrypted_text.bin
       * out: */
      ReadPemAndDecryptMessage();
      break;
    case 3:
      /* in: openssl dgst -sha256 -sign ./private_key.pem -out ./signature.bin ./message.txt
       * out: */
      ReadPemAndVerifyMessage();
      break;
    case 4:
      /* in: openssl rsautl -sign -inkey ./private_key.pem -in ./message.txt -out ./rsautl_signature.bin
       * out: */
      ReadPemAndVerifyMessageWithoutDigest();
      break;
  }
  
  ERR_free_strings();
  EVP_cleanup();
  std::cout << "openssl_learning: end" << std::endl;
  return EXIT_SUCCESS;
}
