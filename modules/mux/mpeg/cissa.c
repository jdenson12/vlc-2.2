/*****************************************************************************
 * libcissa.c: CISSA scrambler/descrambler
 *****************************************************************************
 * Copyright (C) 2004-2005 Laurent Aimar
 * Copyright (C) the deCSA authors
 *
 * Authors: Laurent Aimar <fenrir@via.ecp.fr>
 *          Jean-Paul Saman <jpsaman #_at_# m2x.nl>
 *          Andy Lindsay <a.lindsay@tripleplay.tv>
 *          Jemma Denson <j.denson@tripleplay.tv>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 *****************************************************************************/

/**
  Implements DVB Common IPTV Software-oriented Scrambling Algorithm (CISSA) Version 1
  as described in TS 103127 V1.1.1 using libgcrypt
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <vlc_common.h>

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <vlc_gcrypt.h>
#include "cissa.h"

#define GCRY_CIPHER GCRY_CIPHER_AES128
#define GCRY_MODE GCRY_CIPHER_MODE_CBC

/* cissa control word */
typedef unsigned char		dvbcissa_cw_t[16];
typedef unsigned char		dvbcissa_iv_t[16];

struct dvbcissa_key_s
{
    vlc_object_t *p_caller;
    dvbcissa_iv_t iv;
    gcry_cipher_hd_t handle;
};

/* single packet implementation key context */
typedef struct dvbcissa_key_s dvbcissa_key_t;

static struct dvbcissa_key_s *dvbcissa_key_alloc(vlc_object_t *p_caller);
static void dvbcissa_key_free(struct dvbcissa_key_s *key);
static void dvbcissa_cw_set (const dvbcissa_cw_t cw, struct dvbcissa_key_s *key);
static void dvbcissa_iv_set (const dvbcissa_iv_t iv, struct dvbcissa_key_s *key);
static void dvbcissa_decrypt(struct dvbcissa_key_s *key, unsigned char *data, unsigned char len);
static void dvbcissa_encrypt(struct dvbcissa_key_s *key, unsigned char *data, unsigned char len);

struct cissa_t
{
    /* odd and even keys */
    struct dvbcissa_key_s *o_ck;
    struct dvbcissa_key_s *e_ck;

    bool    use_odd;
};


/*****************************************************************************
 * cissa_New:
 *****************************************************************************/
cissa_t *cissa_New(void)
{
    cissa_t *c;

    c = calloc(1, sizeof(cissa_t));
    if (!c)
        return NULL;

    vlc_gcrypt_init();

    return c;
}

/*****************************************************************************
 * cissa_Delete:
 *****************************************************************************/
void cissa_Delete(cissa_t *c)
{
    if (c->o_ck)
        dvbcissa_key_free(c->o_ck);
    if (c->e_ck)
        dvbcissa_key_free(c->e_ck);
    free(c);
}

/*****************************************************************************
 * cissa_SetCW:
 *****************************************************************************/
int cissa_SetCW(vlc_object_t *p_caller, cissa_t *c, char *psz_ck, bool set_odd)
{
    if (!c) {
        msg_Dbg(p_caller, "no CISSA found");
        return VLC_ENOOBJ;
    }

    /* skip 0x */
    if (psz_ck[0] == '0' && (psz_ck[1] == 'x' || psz_ck[1] == 'X')) {
        psz_ck += 2;
    }

    if (strlen(psz_ck) != 32) {
        msg_Warn(p_caller, "invalid cissa ck (it must be 32 chars long)");
        return VLC_EBADVAR;
    }

    char c_ck[3];
    uint8_t i_ck;
    dvbcissa_cw_t ck;
    int      i;

    // convert hex string into byte array
    for (i = 0; i < 16; i++) {
        memcpy(c_ck, psz_ck + (i * 2), 2);
        c_ck[2] = 0;
        i_ck = strtoul(c_ck, NULL, 16);
        ck[i] = i_ck & 0xff;
    }

#ifndef TS_NO_CISSA_CK_MSG
    msg_Err(p_caller, "using CISSA (de)scrambling with %s "
            "key=%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x", set_odd ? "odd" : "even",
            ck[0], ck[1], ck[2], ck[3], ck[4], ck[5], ck[6], ck[7],
            ck[8], ck[9], ck[10], ck[11], ck[12], ck[13], ck[14], ck[15]);
#endif
    if (set_odd) {
        if (!c->o_ck)
            c->o_ck= dvbcissa_key_alloc(p_caller);

        if (c->o_ck)
            dvbcissa_cw_set(ck, c->o_ck);
    } else {
        if (!c->e_ck)
            c->e_ck= dvbcissa_key_alloc(p_caller);

        if (c->e_ck)
            dvbcissa_cw_set(ck, c->e_ck);
    }

    return VLC_SUCCESS;
}

/*****************************************************************************
 * cissa_UseKey:
 *****************************************************************************/
int cissa_UseKey(vlc_object_t *p_caller, cissa_t *c, bool use_odd)
{
    if (!c)
        return VLC_ENOOBJ;

    c->use_odd = use_odd;
#ifndef TS_NO_CISSA_CK_MSG
        msg_Dbg(p_caller, "using the %s key for scrambling",
                 use_odd ? "odd" : "even");
#endif
    return VLC_SUCCESS;
}

/*****************************************************************************
 * cissa_Decrypt:
 *****************************************************************************/
void cissa_Decrypt(cissa_t *c, uint8_t *pkt, int i_pkt_size)
{
    struct dvbcissa_key_s *ck;

    int     i_hdr, i_len;

    /* transport scrambling control */
    if ((pkt[3] & 0x80) == 0) {
        /* not scrambled */
        return;
    }

    if (pkt[3] & 0x40) {
        ck = c->o_ck;
    } else {
        ck = c->e_ck;
    }

    if (unlikely(!ck)) {
        return;
    }

    /* clear transport scrambling control */
    pkt[3] &= 0x3f;

    i_hdr = 4;
    if (pkt[3] & 0x20) {
        /* skip adaption field */
        i_hdr += pkt[4] + 1;
    }

    if (188 - i_hdr < 8)
        return;

    /* calculate packet size, align to 8 byte boundary */
    i_len = i_pkt_size - i_hdr;
    i_len -= i_len % 8;

    dvbcissa_decrypt(ck, pkt + i_hdr, i_len);
}

/*****************************************************************************
 * cissa_Encrypt:
 *****************************************************************************/
void cissa_Encrypt(cissa_t *c, uint8_t *pkt, int i_pkt_size)
{
    struct dvbcissa_key_s *ck;

    int i_hdr = 4; /* hdr len */
    int i_len;

    /* set transport scrambling control */
    pkt[3] |= 0x80;

    if (c->use_odd) {
        pkt[3] |= 0x40;
        ck = c->o_ck;
    } else {
        ck = c->e_ck;
    }

    if (unlikely(!ck)) {
        return;
    }

    /* hdr len */
    i_hdr = 4;
    if (pkt[3] & 0x20) {
        /* skip adaption field */
        i_hdr += pkt[4] + 1;
    }

    /* calculate packet size, align to 8 byte boundary */
    i_len = i_pkt_size - i_hdr;
    i_len -= i_len % 8;

    dvbcissa_encrypt(ck, pkt + i_hdr, i_len);
}


// Fixed IV
static const dvbcissa_iv_t std_iv = { 0x44, 0x56, 0x42, 0x54, 0x4d, 0x43, 0x50, 0x54, 0x41, 0x45, 0x53, 0x43, 0x49, 0x53, 0x53, 0x41 };


/** allocate a new cissa key context
 *
 * Initialise the library and allocate context space
 *
 */
static struct dvbcissa_key_s *dvbcissa_key_alloc(vlc_object_t *p_caller)
{
    gcry_error_t err;
    struct dvbcissa_key_s *key = calloc(1, sizeof(struct dvbcissa_key_s));

    if (unlikely(!key)) {
        return NULL;
    }

    /* Initialise the library */
    err = gcry_cipher_open(&key->handle, GCRY_CIPHER, GCRY_MODE, 0);
    if (err) {
        msg_Err(p_caller, "Openin AES Cipher failed: %s", gpg_strerror(err));
        free(key);
        return NULL;
    }

    key->p_caller = p_caller;

    /* Install the standard IV */
    dvbcissa_iv_set (std_iv, key);

    return key;
}

/** free a cissa key context */
static void dvbcissa_key_free(struct dvbcissa_key_s *key)
{
    gcry_cipher_close(key->handle);
    free(key);
}

/** setup a cissa key context to use the given control word */
static void dvbcissa_cw_set (const dvbcissa_cw_t cw, struct dvbcissa_key_s *key)
{
    gcry_error_t err;

    err = gcry_cipher_setkey(key->handle, cw, sizeof(dvbcissa_cw_t));
    if (unlikely(err)) {
        msg_Err(key->p_caller, "Setting CISSA AES CW failed: %s", gpg_strerror(err));
    }
}

/** setup a cissa key context to use the given IV */
static void dvbcissa_iv_set (const dvbcissa_iv_t iv, struct dvbcissa_key_s *key)
{
    memcpy(key->iv, iv, sizeof(dvbcissa_iv_t));
}

/** decrypt a packet payload */
static void dvbcissa_decrypt(struct dvbcissa_key_s *key, unsigned char *data, unsigned char len)
{
    gcry_error_t err;
    unsigned char in_len = len - (len % 16);

    if (!in_len) {
        // Nothing to decrypt
        return;
    }

    // CISSA1 uses AES128/CBC and starts again with each packet reset IV each time
    err = gcry_cipher_setiv(key->handle, key->iv, sizeof(dvbcissa_iv_t));
    if (unlikely(err)) {
        msg_Err(key->p_caller, "Setting CISSA AES IV failed: %s", gpg_strerror(err));
        return;
    }

    err = gcry_cipher_decrypt(key->handle, data, in_len, NULL, 0);

    if (unlikely(err)) {
        msg_Err(key->p_caller, "CISSA encryption failed: %s", gpg_strerror(err));
    }
}

/** encrypt a packet payload */
static void dvbcissa_encrypt(struct dvbcissa_key_s *key, unsigned char *data, unsigned char len)
{
    gcry_error_t err;
    unsigned char in_len = len - (len % 16);

    if (!in_len) {
        // Nothing to encrypt
        return;
    }

    // CISSA1 uses AES128/CBC and starts again with each packet reset IV each time
    err = gcry_cipher_setiv(key->handle, key->iv, sizeof(dvbcissa_iv_t));
    if (unlikely(err)) {
        msg_Err(key->p_caller, "Setting CISSA AES IVs failed: %s", gpg_strerror(err));
        return;
    }

    err = gcry_cipher_encrypt(key->handle, data, in_len, NULL, 0);

    if (unlikely(err)) {
        msg_Err(key->p_caller, "CISSA encryption failed: %s", gpg_strerror(err));
    }
}


