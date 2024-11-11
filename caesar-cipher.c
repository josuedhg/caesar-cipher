#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <crypto/internal/skcipher.h>

#define LETTERS_NUMBERS 26
#define BUFFER_SIZE 1024

static char letters_lc[LETTERS_NUMBERS] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
                           'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                           'u', 'v', 'w', 'x', 'y', 'z'};

static char letters_uc[LETTERS_NUMBERS] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                           'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                           'U', 'V', 'W', 'X', 'Y', 'Z'};

static int is_alpha_lower(char c)
{
    return (c >= 'a' && c <= 'z');
}

static int is_alpha_upper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

static char encrypt_char(char c, u8 key)
{
    if (is_alpha_lower(c))
        return letters_lc[(c - 'a' + key) % LETTERS_NUMBERS];
    if (is_alpha_upper(c))
        return letters_uc[(c - 'A' + key) % LETTERS_NUMBERS];

    return c;
}

static char decrypt_char(char c, u8 key)
{
    if (is_alpha_lower(c))
        return letters_lc[(c - 'a' - key + LETTERS_NUMBERS) % LETTERS_NUMBERS];
    if (is_alpha_upper(c))
        return letters_uc[(c - 'A' - key + LETTERS_NUMBERS) % LETTERS_NUMBERS];

    return c;
}

struct caesar_cipher_ctx {
    u8 key;
};

struct caesar_cipher_reqctx {
    struct caesar_cipher_ctx *ctx;
    struct skcipher_request *request;
};

static int caesar_cipher_init(struct crypto_skcipher *tfm)
{
    printk(KERN_INFO "Caesar Cipher Init\n");
    crypto_skcipher_set_reqsize(tfm, sizeof(struct caesar_cipher_reqctx));

    return 0;
}

static void caesar_cipher_exit(struct crypto_skcipher *tfm)
{
    printk(KERN_INFO "Caesar Cipher Exit\n");
}

static int caesar_cipher_encrypt(struct skcipher_request *req)
{
    struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
    struct caesar_cipher_ctx *ctx  = crypto_skcipher_ctx(tfm);
    char buffer[BUFFER_SIZE];
    u8 key = ctx->key;

    sg_copy_to_buffer(req->src, sg_nents(req->src), buffer, req->cryptlen);

    for (int i = 0; i < req->cryptlen; i++) {
        if (!is_alpha_lower(buffer[i]) && !is_alpha_upper(buffer[i])) {
            continue;
        }

        buffer[i] = encrypt_char(buffer[i], key);
    }

    sg_copy_from_buffer(req->dst, sg_nents(req->dst), buffer, req->cryptlen);
    return 0;
}

static int caesar_cipher_decrypt(struct skcipher_request *req)
{
    struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
    struct caesar_cipher_ctx *ctx  = crypto_skcipher_ctx(tfm);
    char buffer[BUFFER_SIZE];
    u8 key = ctx->key;

    sg_copy_to_buffer(req->src, sg_nents(req->src), buffer, req->cryptlen);

    for (int i = 0; i < req->cryptlen; i++) {
        if (!is_alpha_lower(buffer[i]) && !is_alpha_upper(buffer[i])) {
            continue;
        }

        buffer[i] = decrypt_char(buffer[i], key);
    }

    sg_copy_from_buffer(req->dst, sg_nents(req->dst), buffer, req->cryptlen);
    return 0;
}

static int caesar_cipher_setkey(struct crypto_skcipher *tfm, const u8 *key,
                                unsigned int keylen)
{
    struct caesar_cipher_ctx *ctx = crypto_skcipher_ctx(tfm);
    if (keylen != 1) {
        printk(KERN_ERR "Invalid key length %u\n", keylen);
        return -EINVAL;
    }

    ctx->key = key[0];

    printk(KERN_INFO "Caesar Cipher Key: %u\n", ctx->key);

    return 0;
}

struct skcipher_alg caesar_cipher_alg = {
    .base.cra_name = "caesar-cipher",
    .base.cra_driver_name = "caesar-cipher",
    .base.cra_priority = 100,
    .base.cra_flags = CRYPTO_ALG_TYPE_SKCIPHER,
    .base.cra_blocksize = sizeof(struct caesar_cipher_ctx),
    .min_keysize = 1,
    .max_keysize = 1,
    .ivsize = 0,
    .init = caesar_cipher_init,
    .exit = caesar_cipher_exit,
    .setkey = caesar_cipher_setkey,
    .encrypt = caesar_cipher_encrypt,
    .decrypt = caesar_cipher_decrypt,
};

static int __init init_caesar_cipher_module(void)
{
    printk(KERN_INFO "Registering Caesar Cipher\n");
    crypto_register_skcipher(&caesar_cipher_alg);
    return 0;
}

static void __exit cleanup_caesar_cipher_module(void)
{
    printk(KERN_INFO "Removing Caesar Cipher\n");
    crypto_unregister_skcipher(&caesar_cipher_alg);
}

module_init(init_caesar_cipher_module);
module_exit(cleanup_caesar_cipher_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Josue David Hernandez Gutierrez");
MODULE_DESCRIPTION("Caesar Cipher");
