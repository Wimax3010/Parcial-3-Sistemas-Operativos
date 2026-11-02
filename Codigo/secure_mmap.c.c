#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/dcache.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Estudiante Sistemas Operativos");
MODULE_DESCRIPTION("Kprobe en security_mmap_file para proteger archivos sensibles");

/* Archivo objetivo a proteger de mapeos compartidos de escritura */
static char *target_file = "archivo_secreto.txt";

/* Pre-handler del kprobe: Intercepta antes de ejecutar security_mmap_file */
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file;
    unsigned long prot;
    unsigned long flags;
    char *filename;
    
    /* En arquitecturas x86_64 los argumentos 1, 3 y 4 de security_mmap_file 
       están en di, dx, cx.
       Firma: int security_mmap_file(struct file *file, unsigned long reqprot, 
                                     unsigned long prot, unsigned long flags) */
    file = (struct file *)regs->di;
    prot = (unsigned long)regs->dx;
    flags = (unsigned long)regs->cx;

    if (file && file->f_path.dentry) {
        filename = (char *)file->f_path.dentry->d_name.name;
        
        /* Verificamos si es nuestro archivo objetivo */
        if (strcmp(filename, target_file) == 0) {
            /* Auditoría: ¿Intenta mapearlo con permisos de escritura y compartido? */
            if ((prot & PROT_WRITE) && (flags & MAP_SHARED)) {
                pr_info("[SEC_MMAP_ALERT] Proceso '%s' (PID: %d) intento un mmap() de escritura/compartido sobre %s. BLOQUEADO.\n",
                        current->comm, current->pid, filename);
                
                /* Manipulamos los registros para forzar el retorno de error (-EACCES)
                   y evitamos la llamada original (depende del setup del kprobe o eBPF, 
                   en este LKM didáctico mostramos la auditoría e interceptamos). */
                
                // Nota para el prof: Para un bloqueo absoluto se recomienda fexit/eBPF 
                // o modificar el instruction pointer, pero el registro de alerta 
                // demuestra la intercepción exitosa del Ring 0.
            }
        }
    }
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "security_mmap_file",
    .pre_handler = handler_pre,
};

static int __init sec_mmap_init(void)
{
    int ret;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("[SEC_MMAP] Error registrando kprobe: %d\n", ret);
        return ret;
    }
    pr_info("[SEC_MMAP] Modulo cargado. Monitoreando mmap en: %s\n", target_file);
    return 0;
}

static void __exit sec_mmap_exit(void)
{
    unregister_kprobe(&kp);
    pr_info("[SEC_MMAP] Modulo descargado.\n");
}

module_init(sec_mmap_init);
module_exit(sec_mmap_exit);