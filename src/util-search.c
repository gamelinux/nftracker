#include "nftracker.h"
#include "config.h"
#include "bstrlib.h"
#include "common.h"
#include "util-search.h"

extern globalconfig config;


int make_file_signature (const char *sig_start, const char *sig_end, const char *filename);
int add_sig_png (void);
int add_sig_jpg (void);
int add_sig_gif (void);

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
    printf("[*] Added signature for file: %s\n", filename);
    bdestroy(pcre_start);
    bdestroy(pcre_stop);
    return 1;
}

