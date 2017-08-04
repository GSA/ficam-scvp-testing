/**
 * Example C code using libcurl, json-c, and OpenSSL to create a ValidationResult JSON object. 
 *
 * Requirements:
 *
 * json-c - https://github.com/json-c/json-c
 * libcurl - http://curl.haxx.se/libcurl/c
 * 
 * On Ubuntu, you can get json-c via:
 * `sudo apt-get install libjson0 libjson0-dev`
 *
 * Build:
 *
 * gcc HttpClient.c -lcurl -ljson-c -lssl -lcrypto -o HttpClient
 *
 * Run:
 *
 * ./HttpClient
 * 
 * Runtime requirements:
 * 
 * -PEM file with certificate(s) to validate:
 *   `/usr/bin/wget http://fpki-crawler.protiviti.com/fbcaApps/allCerts/paths/CACertificatesValidatingToFederalCommonPolicy.p7b`
 *   `/usr/bin/openssl pkcs7 -in CACertificatesValidatingToFederalCommonPolicy.p7b -inform DER \
 *       -print_certs > CACertificatesValidatingToFederalCommonPolicy.pem`
 * 
 * -Trust in the TLS Server certificate, dependent on the platform and TLS lib (OpenSSL vs. NSS vs. ?).
 *   -The TLS certificate (for the referenced endpoint) is issued by a CA under the Common Policy Root CA
 * 
 * Common Policy Root CA:
 * 
 * -----BEGIN CERTIFICATE-----
 * MIIEYDCCA0igAwIBAgICATAwDQYJKoZIhvcNAQELBQAwWTELMAkGA1UEBhMCVVMx
 * GDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UE
 * AxMYRmVkZXJhbCBDb21tb24gUG9saWN5IENBMB4XDTEwMTIwMTE2NDUyN1oXDTMw
 * MTIwMTE2NDUyN1owWTELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJu
 * bWVudDENMAsGA1UECxMERlBLSTEhMB8GA1UEAxMYRmVkZXJhbCBDb21tb24gUG9s
 * aWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2HX7NRY0WkG/
 * Wq9cMAQUHK14RLXqJup1YcfNNnn4fNi9KVFmWSHjeavUeL6wLbCh1bI1FiPQzB6+
 * Duir3MPJ1hLXp3JoGDG4FyKyPn66CG3G/dFYLGmgA/Aqo/Y/ISU937cyxY4nsyOl
 * 4FKzXZbpsLjFxZ+7xaBugkC7xScFNknWJidpDDSPzyd6KgqjQV+NHQOGgxXgVcHF
 * mCye7Bpy3EjBPvmE0oSCwRvDdDa3ucc2Mnr4MrbQNq4iGDGMUHMhnv6DOzCIJOPp
 * wX7e7ZjHH5IQip9bYi+dpLzVhW86/clTpyBLqtsgqyFOHQ1O5piF5asRR12dP8Qj
 * wOMUBm7+nQIDAQABo4IBMDCCASwwDwYDVR0TAQH/BAUwAwEB/zCB6QYIKwYBBQUH
 * AQsEgdwwgdkwPwYIKwYBBQUHMAWGM2h0dHA6Ly9odHRwLmZwa2kuZ292L2ZjcGNh
 * L2NhQ2VydHNJc3N1ZWRCeWZjcGNhLnA3YzCBlQYIKwYBBQUHMAWGgYhsZGFwOi8v
 * bGRhcC5mcGtpLmdvdi9jbj1GZWRlcmFsJTIwQ29tbW9uJTIwUG9saWN5JTIwQ0Es
 * b3U9RlBLSSxvPVUuUy4lMjBHb3Zlcm5tZW50LGM9VVM/Y0FDZXJ0aWZpY2F0ZTti
 * aW5hcnksY3Jvc3NDZXJ0aWZpY2F0ZVBhaXI7YmluYXJ5MA4GA1UdDwEB/wQEAwIB
 * BjAdBgNVHQ4EFgQUrQx6dVzl85jEeZgOrCj9l/TnAvwwDQYJKoZIhvcNAQELBQAD
 * ggEBAI9z2uF/gLGH9uwsz9GEYx728Yi3mvIRte9UrYpuGDco71wb5O9Qt2wmGCMi
 * TR0mRyDpCZzicGJxqxHPkYnos/UqoEfAFMtOQsHdDA4b8Idb7OV316rgVNdF9IU+
 * 7LQd3nyKf1tNnJaK0KIyn9psMQz4pO9+c+iR3Ah6cFqgr2KBWfgAdKLI3VTKQVZH
 * venAT+0g3eOlCd+uKML80cgX2BLHb94u6b2akfI8WpQukSKAiaGMWMyDeiYZdQKl
 * Dn0KJnNR6obLB6jI/WNaNZvSr79PMUjBhHDbNXuaGQ/lj/RqDG8z2esccKIN47lQ
 * A2EC/0rskqTcLe4qNJMHtyznGI8=
 * -----END CERTIFICATE-----
 * 
 * Based on curltest.c from:
 * https://gist.github.com/leprechau/e6b8fef41a153218e1f4
 * 
 */

/* standard includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

/* json-c (https://github.com/json-c/json-c) */
#include <json-c/json.h>

/* libcurl (http://curl.haxx.se/libcurl/c) */
#include <curl/curl.h>

/* OpenSSL */
#include <openssl/pem.h>

/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};

/* return codes for validate function */
#define SUCCESS     0
#define FAIL        1
#define SERVICEFAIL 2

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
      fprintf(stderr, "ERROR: Failed to expand buffer in curl_callback");
      /* free buffer */
      free(p->payload);
      /* return */
      return -1;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

/* fetch and return url body via curl */
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;                   /* curl result code */

    /* init payload */
    fetch->payload = (char *) calloc(1, sizeof(fetch->payload));

    /* check payload */
    if (fetch->payload == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to allocate payload in curl_fetch_url");
        /* return error */
        return CURLE_FAILED_INIT;
    }

    /* init size */
    fetch->size = 0;

    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);
    
    /* For testing only, should never be used for production  */
    //curl_easy_setopt(ch, CURLOPT_CAPATH, "/etc/ssl/certs/");
    //curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
    
    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) fetch);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 10);

    /* enable location redirects */
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

    /* set maximum allowed redirects */
    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);

    /* fetch the url */
    rcode = curl_easy_perform(ch);

    /* return */
    return rcode;
}

/*
 * This function parses the JSON, logs the result, and 
 * returns 0, 1, or 2 based on the validationResult value.
 */
int validate(json_object *json) {

    const char* success = "SUCCESS";
    const char* fail = "FAIL";
    const char* servicefail = "SERVICEFAIL";
    
    const char* validationResult = NULL;

    json_object *obj_validationResult = json_object_object_get(json, "validationResult");

    if (obj_validationResult != NULL) {
        if (json_object_get_string(obj_validationResult) != NULL) {
            validationResult = json_object_get_string(obj_validationResult);
        } else {
            /* error */
            fprintf(stderr, "ERROR: validationResult does not contain a value");
            /* log the JSON */
            printf("Log Entry: %s\n", json_object_to_json_string(json));
            /* return our answer */
            return SERVICEFAIL;
        }
    } else {
        /* error */
        fprintf(stderr, "ERROR: validationResult is not in the JSON object");
        /* log the JSON */
        printf("Log Entry: %s\n", json_object_to_json_string(json));
        /* return our answer */
        return SERVICEFAIL;
    }
    printf("The result of validation is: %s\n", validationResult);
    if (strcmp(validationResult, success) == 0) {
        /* log the JSON */
        printf("Log Entry: %s\n", json_object_to_json_string(json));
        /* return our answer */
        return SUCCESS;
    } else if (strcmp(validationResult, fail) == 0) {
        /* log the JSON */
        printf("Log Entry: %s\n", json_object_to_json_string(json));
        /* return our answer */
        return FAIL;
    } else if (strcmp(validationResult, servicefail) == 0) {
        /* log the JSON */
        printf("Log Entry: %s\n", json_object_to_json_string(json));
        /* return our answer */
        return SERVICEFAIL;
    } else {
        /* log the JSON */
        printf("Log Entry: %s\n", json_object_to_json_string(json));
        /* return our answer */
        return SERVICEFAIL;
    }
}

/*
 * This function performs the restful call
 */
int restfulValidate(char* base64, char* validationPolicy) {
    CURL *ch;                                               /* curl handle */
    CURLcode rcode;                                         /* curl result code */

    json_object *json;                                      /* json post body */
    enum json_tokener_error jerr = json_tokener_success;    /* json parse error */

    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */
    struct curl_slist *headers = NULL;                      /* http headers to send with request */

    /* url to test site */
    char *url = "https://accpiv.treasury.gov/vss/rest/validate/";

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session\n");
        /* return error */
        return 2;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* create json object for post */
    json = json_object_new_object();

    /* build post data */
    json_object_object_add(json, "validationPolicy", json_object_new_string(validationPolicy));
    json_object_object_add(json, "clientCertificate", json_object_new_string(base64));

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(json));

    /* fetch page and capture return code */
    rcode = curl_fetch_url(ch, url, cf);

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);

    /* free json object */
    json_object_put(json);

    /* check return code */
    if (rcode != CURLE_OK || cf->size < 1) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to fetch url (%s) - curl said: %s\n",
            url, curl_easy_strerror(rcode));
        /* return error */
        return 2;
    }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        printf("CURL Returned: \n%s\n", cf->payload);
        /* parse return */
        json = json_tokener_parse_verbose(cf->payload, &jerr);
        /* free payload */
        free(cf->payload);
    } else {
        /* error */
        fprintf(stderr, "ERROR: Failed to populate payload\n");
        /* free payload */
        free(cf->payload);
        /* return */
        return 2;
    }

    /* check error */
    if (jerr != json_tokener_success) {
        /* error */
        fprintf(stderr, "ERROR: Failed to parse json string\n");
        /* free json object */
        json_object_put(json);
        /* return */
        return 2;
    }

    /* debugging */
    //printf("Parsed JSON: %s\n", json_object_to_json_string(json));
    
    /* validate the result and get our answer */
    int result = validate(json);
    switch (result) {
        case SUCCESS: {
            printf("The certificate was validated successfully, the user may pass.\n");
            break;
        }
        case FAIL: {
            printf("The certificate is not valid, the user shall not pass.\n");
            break;
        }
        case SERVICEFAIL: {
            printf("Unable to validate certificate, the user shall not pass.\n");
            break;
        }
        default: {
            printf("Default: Unable to validate certificate, the user shall not pass.\n");
            break;
        }
    }

    /* free json object */
    json_object_put(json);

    /* exit */
    return result;
}

/*
 * This function loads 1..n PEM encoded certificates
 * from a file.
 */
static STACK_OF(X509) * load_all_certs_from_file(const char *certfile) {

    STACK_OF(X509_INFO) *sk = NULL;
    STACK_OF(X509) *stack = NULL, *ret = NULL;
    BIO *in = NULL;
    X509_INFO *xi;

    if(!(stack = sk_X509_new_null())) {
        printf("memory allocation -1");
        goto end;
    }

    if(!(in=BIO_new_file(certfile, "r"))) {
        printf("error opening the file, %s", certfile);
        sk_X509_free(stack);
        goto end;
    }

    /* This loads from a file, a stack of x509/crl/pkey sets */
    if(!(sk=PEM_X509_INFO_read_bio(in, NULL, NULL, NULL))) {
        printf("error reading the file, %s", certfile);
        sk_X509_free(stack);
        goto end;
    }

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk)) {
        xi = sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack,xi->x509);
            xi->x509=NULL;
        }
        X509_INFO_free(xi);
    }
    if(!sk_X509_num(stack)) {
        printf("no certificates in file, %s", certfile);
        sk_X509_free(stack);
        goto end;
    }
    ret=stack;

    end:
        
    BIO_free(in);
    sk_X509_INFO_free(sk);

    return ret;
}

/*
 * This function encodes data to base64.
 */
char *base64Encode (const void *buffer, int length){
  
    BIO *b64_bio, *mem_bio;
    BUF_MEM *mem_bio_mem_ptr;

    b64_bio = BIO_new(BIO_f_base64());
    mem_bio = BIO_new(BIO_s_mem());

    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64_bio, buffer, length);
    BIO_flush(b64_bio);
    BIO_get_mem_ptr(mem_bio, &mem_bio_mem_ptr);

    BIO_set_close(mem_bio, BIO_NOCLOSE);
    BIO_free_all(b64_bio);

    BUF_MEM_grow(mem_bio_mem_ptr, (*mem_bio_mem_ptr).length + 1);
    (*mem_bio_mem_ptr).data[(*mem_bio_mem_ptr).length] = '\0';
    return (*mem_bio_mem_ptr).data;

}

/*
 * This function works from the stack of certificates
 * retrieved from the PEM file.
 */
void process_stack(STACK_OF(X509)* sk, char* validationPolicy) {

    unsigned len = sk_X509_INFO_num(sk);
    unsigned i;
    X509 *cert;
    for(i=0; i<len; i++) {
        cert = sk_X509_value(sk, i);
        unsigned char* bin = NULL;
	int i2dret = i2d_X509(cert, &bin);
        restfulValidate(base64Encode(bin, i2dret), validationPolicy);
    }

}

/*
 * Our main function.
 */
int main(int argc, char *argv[]) {

    STACK_OF(X509) *certs;
    const char *file = "./CACertificatesValidatingToFederalCommonPolicy.pem";
    char *validationPolicy = "1.3.6.1.5.5.7.19.1";
    BIO *err = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    err = BIO_new_fp(stdout, BIO_NOCLOSE);

    certs = load_all_certs_from_file(file);
    process_stack(certs, validationPolicy);

    /* free resources */
    sk_X509_free(certs);
    BIO_free_all(err);

    /* exit */
    return 0;

}