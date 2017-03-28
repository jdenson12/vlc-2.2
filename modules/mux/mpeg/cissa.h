/*****************************************************************************
 * cissa.h
 *****************************************************************************
 * Copyright (C) 2004 Laurent Aimar
 * $Id$
 *
 * Authors: Laurent Aimar <fenrir@via.ecp.fr>
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

#ifndef VLC_MPEG_CISSA_H_
#define VLC_MPEG_CISSA_H_

typedef struct cissa_t cissa_t;
#define cissa_New     __cissa_New
#define cissa_Delete  __cissa_Delete
#define cissa_SetCW  __cissa_SetCW
#define cissa_UseKey  __cissa_UseKey
#define cissa_Decrypt __cissa_decrypt
#define cissa_Encrypt __cissa_encrypt

cissa_t *cissa_New( void );
void   cissa_Delete( cissa_t * );

int    cissa_SetCW( vlc_object_t *p_caller, cissa_t *c, char *psz_ck, bool odd );
int    cissa_UseKey( vlc_object_t *p_caller, cissa_t *, bool use_odd );

void   cissa_Decrypt( cissa_t *, uint8_t *pkt, int i_pkt_size );
void   cissa_Encrypt( cissa_t *, uint8_t *pkt, int i_pkt_size );

#endif /* _CISSA_H */
