#include "nftracker.h"
#include "config.h"
#include "bstrlib.h"
#include "common.h"
#include "util-search.h"

extern globalconfig config;


int make_file_signature (const char *sig_start, const char *sig_end, const char *filename);
int del_all_sigs_file (void);
int add_sig_png (void);
int add_sig_jpg (void);
int add_sig_gif (void);
int add_sig_cws (void);
int add_sig_fws (void);

int init_sigs (void)
{
    add_sig_pdf();
    add_sig_zip();
    add_sig_html();
    add_sig_doc();
    add_sig_exe();
    add_sig_png();
    add_sig_gif();
    add_sig_jpg();
    add_sig_cws();
    add_sig_fws();
    add_sig_deb();
    //add_sig_tar(); // 75 73 74 61 72
    //add_sig_z(); // 1f 9d
    //add_sig_gzip(); // 1f 8b
    //add_sig_bzip(); // 42 5A 68 39 31 41 59 26 53 59 || 90 40 78 74 9B|%KO%
    return 0;
}

int add_sig_file (signature *sig)
{
    signature *tail;
    tail = config.sig_file;
    if (config.sig_file == NULL) {
        config.sig_file = sig;
        return 0;
    }
    while (tail->next != NULL) {
        tail = tail->next;
    }
    if (tail->next == NULL ) {
        tail->next = sig;
        return 0;
    }
    return 1;
}

int del_all_sigs_file (void)
{
    signature *sig;
    signature *tmp;
    sig = config.sig_file;
    while (sig != NULL) {
        tmp = sig->next;
        if (sig->filetype != NULL) bdestroy(sig->filetype);
        if (sig->regex_start != NULL) free(sig->regex_start);
        if (sig->regex_stop != NULL) free(sig->regex_stop);
        free(sig);
        sig = tmp;
    }
    return 0;
}

int add_sig_deb(void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x21\x3C\x61\x72\x63\x68\x3E\x0A\x64\x65\x62\x69\x61\x6E\x2D\x62\x69\x6E\x61\x72\x79\x20\x20\x20";
    sig_end = "\x20\x20\x60\x0A\x32\x2E\x30\x0A\x63\x6F\x6E\x74\x72\x6F\x6C\x2E\x74\x61\x72\x2E\x67\x7A\x20\x20";
    filename = "deb";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_cws (void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x43\x57\x53[\x06\x07\x08\x09\x10]";
    sig_end = "\x43\x57\x53";
    filename = "cws";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_fws (void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x46\x57\x53[\x04\x05\x06\x07\x08\x09\x10]";
    sig_end = "\x46\x57\x53";
    filename = "fws";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_jpg (void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\xff\xd8\xff\xe0\x00\x10";
    sig_end = "\xff\xd9";
    filename = "jpg";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_gif (void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x47\x49\x46\x38[\x37\x39]\x61";
    sig_end = "\x00?\x00\x3b";
    filename = "gif";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_png (void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x89\x50\x4e\x47";
    sig_end = "\x00\x49\x45\x4E\x44\xAE\x42\x60\x82";
    filename = "png";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_pdf(void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x25\x50\x44\x46";
    sig_end = "\x25\x45\x4F\x46";
    filename = "pdf";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_zip(void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x50\x4B\x03\x04";
    sig_end = "\x3c\xac";
    filename = "zip";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_html(void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\x3Chtml";
    sig_end = "\x3C\x2Fhtml\x3E";
    filename = "html";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_doc(void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
    sig_end = "MSWordDoc";
    filename = "doc";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int add_sig_exe(void)
{
    const char *sig_start;
    const char *sig_end;
    const char *filename;

    sig_start = "MZ\0\0\0\0\0\0\0\0\0\0PE";
    sig_end = "This program cannot be run in DOS mode.|Windows Program|This program must be ";
    filename = "exe";
    make_file_signature(sig_start, sig_end, filename);
    return 0;
}

int make_file_signature (const char *sig_start, const char *sig_end, const char *filename)
{
    const char *err = NULL;     /* PCRE */
    int erroffset;              /* PCRE */
    bstring pcre_start = NULL;
    bstring pcre_stop = NULL;
    signature *sig;

    sig = (signature *) calloc(1, sizeof(signature));

    sig->next = NULL;
    sig->prev = NULL;
    pcre_start = bfromcstr(sig_start);
    pcre_stop = bfromcstr(sig_end);
    sig->filetype = bfromcstr(filename);

    sig->regex_start = pcre_compile((char *)bdata(pcre_start), 0, &err, &erroffset, NULL);
    sig->regex_stop = pcre_compile((char *)bdata(pcre_stop), 0, &err, &erroffset, NULL);
    sig->study_start = pcre_study(sig->regex_start, 0, &err);
    sig->study_stop = pcre_study(sig->regex_stop, 0, &err);

    add_sig_file(sig);
    if (ISSET_CONFIG_VERBOSE(config)) printf("[*] Added signature for file: %s\n", filename);
    bdestroy(pcre_start);
    bdestroy(pcre_stop);
    return 1;
}



