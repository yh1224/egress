/**
 * @file
 * Egress encoder/decoder header
 */
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern int yyparse();

/**
 * element type
 */
typedef enum eg_type {
    EG_TYPE_NONE = 0,
    EG_TYPE_KEYWORD,    /* keyword (auto, random, ...) */
    EG_TYPE_NUMBER,     /* numveric value */
    EG_TYPE_MACADDR,    /* mac address (EUI-48) */
    EG_TYPE_IPV4ADDR,   /* IPv4 address */
    EG_TYPE_IPV6ADDR,   /* IPv6 address */
    EG_TYPE_STRING,     /* string */
} eg_type_t;

/**
 * element value
 */
typedef struct eg_elem_val {
    enum eg_type type;      /* element type */
    char *str;              /* element body */
} eg_elem_val_t;

/**
 * element
 */
typedef struct eg_elem {
    struct eg_elem *next;       /* next sibling element */
    char *name;                 /* element name */
    eg_elem_val_t *val;         /* element value */
    struct eg_elem *elems;      /* sub-elements */
} eg_elem_t;

eg_elem_t *get_element_top();

/**
 * buffer for encode
 */
typedef struct eg_buffer {
    struct eg_buffer *next;     /* buffer chain */
    u_int8_t *ptr;              /* buffer pointer */
    int len;                    /* buffer length */
    int size;                   /* buffer size */
} eg_buffer_t;

/**
 * encoder definition
 */
typedef struct eg_enc_encoder {
    int id;                     /* identification */
    char *name;                 /* element name */
    char *desc;                 /* description */
    eg_buffer_t *(*encode)(struct eg_elem *, void *upper); /* encode function */
} eg_enc_encoder_t;

/**
 * number definition
 */
typedef struct eg_enc_vals {
    char *name;                 /* keyword */
    char *desc;                 /* description */
    u_int32_t val;              /* number value */
} eg_enc_vals_t;

eg_enc_encoder_t *eg_enc_get_encoder(char *name, eg_enc_encoder_t *encoders);
eg_buffer_t *eg_enc_encode(eg_elem_t *elems);

/* block encoder */
eg_buffer_t *eg_enc_encode_ether(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_vlan(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_arp(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_ipv4(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_ipv6(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_icmp(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_tcp(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_udp(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_icmpv6(struct eg_elem *, void *upper);
eg_buffer_t *eg_enc_encode_raw(struct eg_elem *, void *upper);

/* common field encoder */
int eg_enc_encode_uint(u_int32_t *result, eg_elem_val_t *val, u_int32_t min, u_int32_t max);
int eg_enc_encode_uint32(u_int32_t *result, eg_elem_val_t *val);
int eg_enc_encode_uint16(u_int16_t *result, eg_elem_val_t *val);
int eg_enc_encode_uint8(u_int8_t *result, eg_elem_val_t *val);
int eg_enc_encode_hex(u_int8_t *result, eg_elem_val_t *val, int min, int max);
int eg_enc_encode_macaddr(u_int8_t *result, eg_elem_val_t *val);
int eg_enc_encode_ipv4addr(struct in_addr *result, eg_elem_val_t *val);
int eg_enc_encode_ipv6addr(struct in6_addr *result, eg_elem_val_t *val);
int eg_enc_encode_name_uint32(u_int32_t *result, eg_elem_val_t *val, eg_enc_vals_t *encname);
int eg_enc_encode_name_uint16(u_int16_t *result, eg_elem_val_t *val, eg_enc_vals_t *encname);
int eg_enc_encode_name_uint8(u_int8_t *result, eg_elem_val_t *val, eg_enc_vals_t *encname);
int eg_enc_encode_flags_uint32(u_int32_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags);
int eg_enc_encode_flags_uint16(u_int16_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags);
int eg_enc_encode_flags_uint8(u_int8_t *result, eg_elem_val_t *val, eg_enc_vals_t *encflags);

/* compare shortcut */
static inline int eg_enc_elem_name_is(eg_elem_t *elem, char *name) {
    return !strcasecmp(elem->name, name);
}
static inline int eg_enc_val_is_keyword(eg_elem_val_t *val, char *keyword) {
    return (val->type == EG_TYPE_KEYWORD && !strcasecmp(val->str, keyword));
}

/* buffer operation */
eg_buffer_t *eg_buffer_create(int len);
eg_buffer_t *eg_buffer_resize(eg_buffer_t *buf, int newlen);
void eg_buffer_destroy(eg_buffer_t *buf);
eg_buffer_t *eg_buffer_chain(eg_buffer_t *buf1, eg_buffer_t *buf2);
eg_buffer_t *eg_buffer_merge(eg_buffer_t *buf1, eg_buffer_t *buf2, int offset);

/**
 * pseudo header for calculate IPv4 checksum
 */
struct ipv4_pseudo_header {
    struct in_addr src;
    struct in_addr dst;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t len;
};

/**
 * pseudo header for calculate IPv6 checksum
 */
struct ipv6_pseudo_header {
    struct in6_addr src;
    struct in6_addr dst;
    u_int32_t plen;
    u_int8_t zero[3];
    u_int8_t nxt;
};
