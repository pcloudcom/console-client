/* Copyright (c) 2015 Anton Titov.
 * Copyright (c) 2015 pCloud Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of pCloud Ltd nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _PSYNC_COMPRESSION_H
#define _PSYNC_COMPRESSION_H

struct _psync_deflate_t;

typedef struct _psync_deflate_t psync_deflate_t;

#define PSYNC_DEFLATE_DECOMPRESS   0
#define PSYNC_DEFLATE_COMP_FASTEST 1
#define PSYNC_DEFLATE_COMP_FAST    2
#define PSYNC_DEFLATE_COMP_MED     6
#define PSYNC_DEFLATE_COMP_BEST    9

#define PSYNC_DEFLATE_NOFLUSH    0
#define PSYNC_DEFLATE_FLUSH      1
#define PSYNC_DEFLATE_FLUSH_END  2

#define PSYNC_DEFLATE_NODATA       -1
#define PSYNC_DEFLATE_FULL         -2
#define PSYNC_DEFLATE_ERROR        -3
#define PSYNC_DEFLATE_EOF          0


psync_deflate_t *psync_deflate_init(int level);
void psync_deflate_destroy(psync_deflate_t *def);
int psync_deflate_write(psync_deflate_t *def, const void *data, int len, int flush);
int psync_deflate_read(psync_deflate_t *def, void *data, int len);
int psync_deflate_pending(psync_deflate_t *def);

#endif
