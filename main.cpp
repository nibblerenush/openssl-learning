#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <errno.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

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

std::string GetLinuxErrorString()
{
  std::ostringstream ostringstream;
  ostringstream << strerror(errno);
  return ostringstream.str();
}

void GetFileData(std::unique_ptr<unsigned char[]> & data, std::size_t & size, const char * fileName)
{
  std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(fileName, "rb"), &std::fclose);
  if (!file)
  {
    throw std::runtime_error(GetLinuxErrorString());
  }
  
  if (std::fseek(file.get(), 0, SEEK_END) == -1)
  {
    throw std::runtime_error(GetLinuxErrorString());
  }
  size = std::ftell(file.get());
  if (size == -1)
  {
    throw std::runtime_error(GetLinuxErrorString());
  }
  if (std::fseek(file.get(), 0, SEEK_SET) == -1)
  {
    throw std::runtime_error(GetLinuxErrorString());
  }
  
  data = std::unique_ptr<unsigned char[]>(new unsigned char [size]);
  if (std::fread( data.get(), size, 1, file.get()) == 0)
  {
    throw std::runtime_error(GetLinuxErrorString());
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
      throw std::runtime_error(GetLinuxErrorString());
    }
    if (!PEM_write_PUBKEY(pemFilePublicKey.get(), pkey.get()))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> pemFilePrivateKey(fopen("private_key.pem", "wb"), &std::fclose);
    if (!pemFilePrivateKey)
    {
      throw std::runtime_error(GetLinuxErrorString());
    }
    if (!PEM_write_PrivateKey(pemFilePrivateKey.get(), pkey.get(), nullptr, nullptr, 0, nullptr, nullptr))
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
      throw std::runtime_error(GetLinuxErrorString());
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

void VerifyMessage()
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
      throw std::runtime_error(GetLinuxErrorString());
    }
    EVP_PKEY * rawPkey;
    if (!PEM_read_PUBKEY(pemFilePublicKey.get(), &rawPkey, nullptr, nullptr))
    {
      throw std::runtime_error(GetSslErrorString());
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(rawPkey, &EVP_PKEY_free);
    
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

int main()
{
  std::cout << "openssl_learning: start" << std::endl;
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  //GenerateRsaAndWritePem();
  
  //openssl rsautl -encrypt -inkey ./public_key.pem -pubin -out encrypted_text.bin
  //ReadPemAndDecryptMessage();
  
  //openssl dgst -sha256 -sign ./private_key.pem -out signature.bin ./message.txt
  VerifyMessage();
  
  ERR_free_strings();
  EVP_cleanup();
  std::cout << "openssl_learning: end" << std::endl;
  return EXIT_SUCCESS;
}
