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
    
    SSL_CTX_set_verify(sslContext.get(), SSL_VERIFY_PEER, nullptr);
    
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
    std::cout << GetX509CertInfo(x509ServerCert.get()) << std::endl;
    
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
  
//   long res = 1;
//   
// 
// SSL_CTX* ctx = NULL;
// BIO *web = NULL, *out = NULL;
// SSL *ssl = NULL;
// 
//   (void)
// 
//   SSL_load_error_strings();
//   ();
//   ();
// 
// 
// if(!(NULL != method)) handleFailure(__LINE__);
// 
// ctx = SSL_CTX_new(method);
// if(!(ctx != NULL)) handleFailure(__LINE__);
// 
// /* Cannot fail ??? */
// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
// 
// /* Cannot fail ??? */
// SSL_CTX_set_verify_depth(ctx, 4);
// 
// /* Cannot fail ??? */
// //const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
// //SSL_CTX_set_options(ctx, flags);
// 
// res = SSL_CTX_set_default_verify_paths(ctx);
// if(!(1 == res)) handleFailure(__LINE__);
// 
// /*res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
// if(!(1 == res)) handleFailure(__LINE__);*/
// 
// web = BIO_new_ssl_connect(ctx);
// if(!(web != NULL)) handleFailure(__LINE__);
// 
// res = BIO_set_conn_hostname(web, HOST_NAME ":" HOST_PORT);
// if(!(1 == res)) handleFailure(__LINE__);
// 
// BIO_get_ssl(web, &ssl);
// if(!(ssl != NULL)) handleFailure(__LINE__);
// 
// /*const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
// res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
// if(!(1 == res)) handleFailure(__LINE__);*/
// 
// res = SSL_set_tlsext_host_name(ssl, HOST_NAME);
// if(!(1 == res)) handleFailure(__LINE__);
// 
// out = BIO_new_fp(stdout, BIO_NOCLOSE);
// if(!(NULL != out)) handleFailure(__LINE__);
// 
// res = BIO_do_connect(web);
// if(!(1 == res)) handleFailure(__LINE__);
// 
// /*res = SSL_connect(ssl);
// if(!(1 == res)) handleFailure(__LINE__);*/
// res = BIO_do_handshake(web);
// if(!(1 == res)) handleFailure(__LINE__);
// 
// /* Step 1: verify a server certificate was presented during the negotiation */
// X509* cert = SSL_get_peer_certificate(ssl);
// if(cert) { X509_free(cert); } /* Free immediately */
// if(NULL == cert) handleFailure(__LINE__);
// 
// /* Step 2: verify the result of chain verification */
// /* Verification performed according to RFC 4158    */
// res = SSL_get_verify_result(ssl);
// if(!(X509_V_OK == res)) handleFailure(__LINE__);
// 
// /* Step 3: hostname verification */
// /* An exercise left to the reader */
// 
// /*BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\n"
//               "Host: " HOST_NAME "\r\n"
//               "Connection: close\r\n\r\n");*/
// 
// BIO_puts(web, "GET " HOST_RESOURCE " HTTP/1.1\r\n"
//               "Host: " HOST_NAME "\r\n"
//               "Connection: close\r\n\r\n");
// 
// BIO_puts(out, "\n");
// 
// int len = 0;
// do
// {
//   char buff[1536] = {};
//   len = BIO_read(web, buff, sizeof(buff));
//             
//   if(len > 0)
//     BIO_write(out, buff, len);
// 
// } while (len > 0 || BIO_should_retry(web));
// 
// if(out)
//   BIO_free(out);
// 
// if(web != NULL)
//   BIO_free_all(web);
// 
// if(NULL != ctx)
//   SSL_CTX_free(ctx);
// return 0;
// }
// 
// 
// 
// void handleFailure(int g)
// {
//   std::cerr << "fail :" << g << '\n';
// }
// 
// int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
// {
//     int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
//     int err = X509_STORE_CTX_get_error(x509_ctx);
//     
//     X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
//     X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
//     X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
//     
//     std::cout << "Issuer (cn)" << iname;
//     std::cout << "Subject (cn)" << sname;
//     
//     if(depth == 0) {
//         /* If depth is 0, its the server's certificate. Print the SANs too */
//         std::cout << "Subject (san)" << cert;
//     }
// 
//     return preverify;
// }
