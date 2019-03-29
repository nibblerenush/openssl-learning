#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

std::string GetSslInfo()
{
  std::ostringstream ostringstream;
  ostringstream
    << SSLeay_version(SSLEAY_VERSION) << '\n'
    << SSLeay_version(SSLEAY_CFLAGS) << '\n'
    << SSLeay_version(SSLEAY_BUILT_ON) << '\n'
    << SSLeay_version(SSLEAY_PLATFORM) << '\n'
    << SSLeay_version(SSLEAY_DIR) << '\n';
  return ostringstream.str();
}

std::string GetSslErrorString(int line)
{
  unsigned long error = ERR_get_error();
  std::ostringstream ostringstream;
  ostringstream
    << "Line: " << line << '\n'
    << ERR_error_string(error, nullptr) << '\n'
    << "lib: " << ERR_lib_error_string(error) << '\n'
    << "func: " << ERR_func_error_string(error) << '\n'
    << "reason: " << ERR_reason_error_string(error);
  return ostringstream.str();
}

std::string GetOsErrorString(int line)
{
  std::ostringstream ostringstream;
  ostringstream
    << "Line: " << line << '\n'
    << std::strerror(errno);
  return ostringstream.str();
}

std::string GetX509CertInfo(X509 * x509Cert)
{
  std::size_t issuerSize = 512;
  std::unique_ptr<char []> issuer = std::unique_ptr<char []>(new char [issuerSize]);
  if (!X509_NAME_oneline(X509_get_issuer_name(x509Cert), issuer.get(), issuerSize))
  {
    throw std::runtime_error(GetSslErrorString(__LINE__));
  }
  
  std::size_t subjectSize = 512;
  std::unique_ptr<char []> subject = std::unique_ptr<char []>(new char [subjectSize]);
  if (!X509_NAME_oneline(X509_get_subject_name(x509Cert), subject.get(), subjectSize))
  {
    throw std::runtime_error(GetSslErrorString(__LINE__));
  }
  
  std::ostringstream ostringstream;
  ostringstream
    << "Issuer: " << issuer.get() << '\n'
    << "Subject: " << subject.get();
  return ostringstream.str();
}

int VerifyCallback(int preverifyOk, X509_STORE_CTX * x509StoreContext)
{
  std::cout << "=== " << __FUNCTION__ << ": start" << " ===" << std::endl;
  std::cout << "preverifyOk: " << preverifyOk << std::endl;
  
  int error = X509_STORE_CTX_get_error(x509StoreContext);
  std::cout << "error: " << X509_verify_cert_error_string(error) << std::endl;
  
  int depth = X509_STORE_CTX_get_error_depth(x509StoreContext);
  std::cout << "depth: " << depth << std::endl;
  
  X509 * mainCert = X509_STORE_CTX_get_current_cert(x509StoreContext);
  if (mainCert)
  {
    std::cout << "mainCert: \n" << GetX509CertInfo(mainCert) << std::endl;
  }
  
  STACK_OF(X509) * x509Stack = X509_STORE_CTX_get1_chain(x509StoreContext);
  while (X509 * certInChain = sk_X509_pop(x509Stack))
  {
    std::cout << "certInChain: \n" << GetX509CertInfo(certInChain) << std::endl;
  }
  
  sk_X509_pop_free(x509Stack, X509_free);
  std::cout << "=== " << __FUNCTION__ << ": end" << " ===" << std::endl;
  return preverifyOk;
}

struct Host
{
  std::string name;
  std::string port;
  std::string resource;
};

int main(int argc, char ** argv)
{
  if (argc != 4)
  {
    std::cerr << "Usage: openssl-learning-ssl [host_name] [host_port] [host_resource]" << std::endl;
    return EXIT_FAILURE;
  }
  
  std::cout << GetSslInfo() << std::endl;
  std::cout << argv[0] << ": start\n" << std::endl;
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  
  try
  {
    struct Host host = {argv[1], argv[2], argv[3]};
    
    const SSL_METHOD * sslMethod = SSLv23_method();
    if (!sslMethod)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslContext(SSL_CTX_new(sslMethod), &SSL_CTX_free);
    if (!sslContext)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    SSL_CTX_set_verify(sslContext.get(), SSL_VERIFY_PEER, VerifyCallback);
    
    if (!SSL_CTX_set_default_verify_paths(sslContext.get()))
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    std::unique_ptr<BIO, decltype(&BIO_free_all)> webBio(BIO_new_ssl_connect(sslContext.get()), &BIO_free_all);
    if (!webBio)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    std::string hostname = host.name + ':' + host.port;
    if (!BIO_set_conn_hostname(webBio.get(), hostname.c_str()))
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    SSL * ssl;
    BIO_get_ssl(webBio.get(), &ssl);
    if (!ssl)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    if (!BIO_do_connect(webBio.get()))
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    if (!BIO_do_handshake(webBio.get()))
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    std::unique_ptr<X509, decltype(&X509_free)> x509ServerCert(SSL_get_peer_certificate(ssl), &X509_free);
    if (!x509ServerCert)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    std::cout << "Server certificate: \n" << GetX509CertInfo(x509ServerCert.get()) << std::endl;
    
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    std::string request =
      std::string("GET ") + host.resource + " HTTP/1.1\r\n" +
      std::string("Host: ") + host.name + "\r\n" +
      std::string("Connection: close\r\n\r\n");
    
    if (BIO_write(webBio.get(), request.c_str(), request.size()) <= 0)
    {
      throw std::runtime_error(GetSslErrorString(__LINE__));
    }
    
    std::unique_ptr<std::FILE, decltype(&std::fclose)> outputFile(std::fopen("output.html", "w"), &std::fclose);
    if (!outputFile)
    {
      throw std::runtime_error(GetOsErrorString(__LINE__));
    }
    
    int length = 0;
    do
    {
      char buffer [1024] = {};
      length = BIO_read(webBio.get(), buffer, sizeof(buffer));
      
      if(length > 0)
      {
        std::fwrite(buffer, sizeof(buffer[0]), sizeof(buffer), outputFile.get());
      }
    }
    while (length > 0 || BIO_should_retry(webBio.get()));
  }
  catch (std::runtime_error ex)
  {
    std::cerr << ex.what() << std::endl;
  }
  
  ERR_free_strings();
  EVP_cleanup();
  std::cout << '\n' << argv[0] << ": end" << std::endl;
  return EXIT_SUCCESS;
}
