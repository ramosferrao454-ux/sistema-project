#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <asm/errno.h>

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char __user *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char __user *, size_t, loff_t *);

#define SUCCESS 0
#define DEVICE_NAME "UZ_Device"  // MODIFICADO: Nome alterado conforme especificado
#define BUF_LEN 80

static int major;
static int counter = 0;  // MODIFICADO: Movido para escopo global

enum {
    CDEV_NOT_USED = 0,
    CDEV_EXCLUSIVE_OPEN = 1,
};

static atomic_t already_open = ATOMIC_INIT(CDEV_NOT_USED);
static char msg[BUF_LEN + 1];
static struct class *cls;

static struct file_operations chardev_fops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
};

static int __init entrada(void) {
    major = register_chrdev(0, DEVICE_NAME, &chardev_fops);

    if (major < 0) {
        pr_alert("O registro do dispositivo em caracter falhou com %d\n", major);
        return major;
    }
    pr_info("foi atribuido o numero maior %d\n", major);

    cls = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(cls, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    pr_info("Dispositivo criado em /dev/%s\n", DEVICE_NAME);
    return SUCCESS;
}

static void __exit saida(void) {
    device_destroy(cls, MKDEV(major, 0));
    class_destroy(cls);
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("Dispositivo removido\n");
}

static int device_open(struct inode *inode, struct file *file) {
    if (atomic_cmpxchg(&already_open, CDEV_NOT_USED, CDEV_EXCLUSIVE_OPEN))
        return -EBUSY;

    try_module_get(THIS_MODULE);
    sprintf(msg, "ja informei-te %d vezes ola o mundo de kernel linux!\n", counter++);
    return SUCCESS;
}

static int device_release(struct inode *inode, struct file *file) {
    atomic_set(&already_open, CDEV_NOT_USED);
    module_put(THIS_MODULE);
    return SUCCESS;
}

static ssize_t device_read(struct file *filp, char __user *buffer,
                          size_t length, loff_t *offset) {
    int bytes_read = 0;
    const char *msg_ptr = msg;

    if (!*(msg_ptr + *offset)) {
        *offset = 0;
        return 0;
    }
    msg_ptr += *offset;

    while (length && *msg_ptr) {
        if (put_user(*(msg_ptr++), buffer++))
            return -EFAULT;
        length--;
        bytes_read++;
    }

    *offset += bytes_read;
    return bytes_read;
}

// MODIFICADO: Função write implementada
static ssize_t device_write(struct file *filp, const char __user *buff,
                           size_t len, loff_t *off) {
    int ret;
    char temp[BUF_LEN + 1];

    // Limitar o tamanho da escrita
    if (len > BUF_LEN)
        len = BUF_LEN;

    // Copiar dados do espaço do usuário para o kernel
    ret = copy_from_user(temp, buff, len);
    if (ret) {
        pr_alert("Erro ao copiar dados do usuario: %d\n", ret);
        return -EFAULT;
    }

    temp[len] = '\0'; // Garantir terminação nula

    // Copiar para a mensagem global
    strncpy(msg, temp, BUF_LEN);
    msg[BUF_LEN] = '\0';

    pr_info("Mensagem recebida: %s\n", msg);

    return len;
}

module_init(entrada);
module_exit(saida);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("RMI");
MODULE_DESCRIPTION("MODULO PARA LEITURA E ESCRITA DE UM DISPOSITIVO EM CARACTER");
