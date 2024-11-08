#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/printk.h>

static int __init init_caesar_cipher(void)
{
    printk(KERN_INFO "Caesar Cipher loaded\n");
    return 0;
}

static void __exit cleanup_caesar_cipher(void)
{
    printk(KERN_INFO "Caesar Cipher unloaded\n");
}

module_init(init_caesar_cipher);
module_exit(cleanup_caesar_cipher);

MODULE_LICENSE("GPL v3");
MODULE_AUTHOR("Josue David Hernandez Gutierrez");
MODULE_DESCRIPTION("Caesar Cipher");
