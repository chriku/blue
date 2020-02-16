local ffi = require "ffi"
ffi.cdef [[
void *malloc(size_t size);
void free(void *ptr);
typedef struct EVP_MD_CTX {} EVP_MD_CTX;
typedef struct HMAC_CTX {} HMAC_CTX;
typedef struct EVP_MD {} EVP_MD;
typedef struct EVP_CIPHER {} EVP_CIPHER;
typedef struct EVP_CIPHER_CTX {} EVP_CIPHER_CTX;
typedef struct X509 {} X509;
typedef struct EVP_PKEY {} EVP_PKEY;
typedef struct EVP_PKEY_CTX {} EVP_PKEY_CTX;
typedef struct ENGINE {} ENGINE;
typedef struct RSA {} RSA;
const EVP_CIPHER *EVP_aes_128_ctr(void);
const EVP_CIPHER *EVP_aes_256_ctr(void);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
int RAND_bytes(unsigned char *buf, int num);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *c);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
HMAC_CTX *HMAC_CTX_new(void);
void HMAC_CTX_free(HMAC_CTX *ctx);
int HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,const EVP_MD *md, ENGINE *impl);
int HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
const EVP_MD *EVP_sha256(void);
int HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, int len);
EVP_PKEY_CTX *EVP_PKEY_CTX_new_id(int id, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_CTX_ctrl(EVP_PKEY_CTX *ctx, int keytype, int optype,
                              int cmd, int p1, void *p2);
const EVP_MD *EVP_sha256(void);
int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);


int i2d_RSAPublicKey(RSA *a, unsigned char **pp);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
X509 *d2i_X509(X509 **a, unsigned char **ppin, long length);
void X509_free(X509 *a);
EVP_PKEY *X509_get_pubkey(X509 *x);
void EVP_PKEY_free(EVP_PKEY *key);
EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *ctx);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *ctx,unsigned char *rout, size_t *routlen,const unsigned char *sig, size_t siglen);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *pkey, unsigned char *pub,size_t *len);
const EVP_MD *EVP_sha1(void);
const EVP_MD *EVP_sha3_256(void);

const EVP_MD *EVP_shake256(void);
int EVP_DigestFinalXOF(EVP_MD_CTX *ctx, unsigned char *md, size_t len);

]]
return ffi.load("/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1")
