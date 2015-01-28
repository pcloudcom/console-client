/* Copyright (c) 2014 Anton Titov.
 * Copyright (c) 2014 pCloud Ltd.
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

#include "ppassword.h"
#include "ppassworddict.h"
#include "plibs.h"
#include "pssl.h"
#include <string.h>
#include <ctype.h>

static int find_in_dict(const unsigned char *pwd, size_t len){
  size_t hi, lo, med, l;
  int c;
  if (len>8)
    len=8;
  else if (len<=3)
    return 0;
  lo=0;
  hi=ARRAY_SIZE(passworddict);
  while (lo<hi){
    med=(lo+hi)/2;
    l=len;
    while (l && passworddict[med][l-1]==0)
      l--;
    c=memcmp(pwd, passworddict[med], l);
    if (c<0)
      hi=med;
    else if (c>0)
      lo=med+1;
    else{
//      if (l==8 || passworddict[med][l]==0){
        while (l<8 && l<=len && med<ARRAY_SIZE(passworddict) && !memcmp(pwd, passworddict[med+1], l+1)){
          hi=len;
          med++;
          while (hi>0 && passworddict[med][hi-1]==0)
            hi--;
          if (memcmp(pwd, passworddict[med], hi))
            break;
          else
            l=hi;
        }
//        debug(D_NOTICE, "pwd=%s l=%lu", pwd, (unsigned long)l);
        return l;
/*      }
      else
        hi--;*/
    }
  }
  return 0;
}

static int is_punct(int c){
  return strchr("!@#$%^&*()_+[]{},.<>:;'\"`\\/~|", c)!=NULL;
}

#define mul_score(num) do{\
  oscore=score;\
  score*=num;\
  if (unlikely(oscore>score)){\
    debug(D_NOTICE, "got overflow");\
    return ~((uint64_t)0);\
  }\
} while (0)

static uint64_t trailing_num_score(uint64_t num, size_t numlen, const unsigned char *nstr){
  uint64_t score, oscore;
  size_t i, j;
  if (numlen==1){
    if (num<=1)
      return 2;
    else
      return 5;
  }
  else if (numlen==2){ // chances are too high that this might be a guessable year
    if (num==11)
      return 2;
    else if (num==69 || num%10==num/10 || num%10+1==num/10)
      return 4;
    else
      return 8;
  }
  else if (numlen==4 && num>=1900 && num<=2030) // probably a year
    return 10;
  if (nstr[0]=='1')
    score=1;
  else if (nstr[0]=='0')
    score=2;
  else
    score=8;
  i=1;
  do {
    for (j=i; j>0; j--)
      if (i+j<=numlen && !memcmp(nstr+i, nstr+i-j, j)){
        mul_score(2);
        i+=j;
        goto ex;
      }
    if (nstr[i]==nstr[i-1] || nstr[i]==nstr[i-1]+1 || nstr[i]==nstr[i-1]-1)
      mul_score(2);
    else
      mul_score(10);
    i++;
  ex:;
  } while (i<numlen);
  return score;
}

static int keyboard_buddies(int ch1, int ch2){
  static const char *kb="qwertyuiop[]asdfghjkl;'\\zxcvbnm,./QWERTYUIOP{}ASDFGHJKL:\"|ZXCVBNM<>?~!@#$%^&*()_+";
  char *f;
  f=strchr(kb, ch1);
  return f && (f[1]==ch2 || (f>kb && *(f-1)==ch2));
}

static uint64_t score_variants(const unsigned char *password, const unsigned char *lpassword, const unsigned char *npassword, size_t plen){
  uint64_t score, oscore;
  size_t off, r, numchars, n, j;
  int d, haslow, hasup, hasnum, haspunct, hasspace, hasother;
  char ch, pch;
  off=0;
  score=1;
  haslow=hasup=hasnum=haspunct=hasspace=hasother=0;
  numchars=0;
  while (off<plen){
    r=plen-off;
    d=find_in_dict(password+off, r);
    if (d){
      mul_score(ARRAY_SIZE(passworddict)/32*d);
      off+=d;
      continue;
    }
    d=find_in_dict(lpassword+off, r);
    if (d){
      mul_score(ARRAY_SIZE(passworddict)/16*d);
      off+=d;
      continue;
    }
    d=find_in_dict(npassword+off, r);
    if (d){
      mul_score(ARRAY_SIZE(passworddict)/8*d);
      off+=d;
      continue;
    }
    if (islower(password[off]))
      haslow=1;
    else if (isupper(password[off]))
      hasup=1;
    else if (isdigit(password[off]))
      hasnum=1;
    else if (is_punct(password[off]))
      haspunct=1;
    else if (isspace(password[off]))
      hasspace=1;
    else
      hasother=1;
    ch=password[off];
    if (!off){
      if (ch=='a')
        mul_score(2);
      else if (ch=='q')
        mul_score(2);
      else if (ch=='z')
        mul_score(4);
      else if (ch=='1')
        mul_score(2);
      else
        numchars++;
    }
    else{
      for (j=off; j>0; j--)
        if (j<=r){
          if (!memcmp(password+off, password+off-j, j)){
            mul_score(1+j);
            off+=j;
            goto ex;
          }
          else if (!memcmp(lpassword+off, lpassword+off-j, j)){
            mul_score(2+j);
            off+=j;
            goto ex;
          }
        }
      pch=password[off-1];
      if (pch+1==ch || pch-1==ch)
        mul_score(2);
      else if (keyboard_buddies(pch, ch))
        mul_score(2);
      else if (keyboard_buddies(lpassword[off-1], lpassword[off]))
        mul_score(4);
      else
        numchars++;
    }
    off++;
ex:;
  }
  n=0;
  if (haslow)
    n+=26;
  if (hasup)
    n+=26;
  if (hasnum)
    n+=10;
  if (haspunct)
    n+=20;
  if (hasspace)
    n+=2;
  if (hasother)
    n+=10;
  while (numchars--)
    mul_score(n);
  return score;
}

static uint64_t uint_sqrt(uint64_t n){
  uint64_t h, l, m, m2;
  h=n/2;
  l=1;
  m=1;
  if (n==1)
    return 1;
  while (h>l+1){
    m=(h+l)/2;
    m2=m*m;
    if (m2>n)
      h=m;
    else if (m2<n)
      l=m;
    else
      break;      
  }
  return m;
}

uint64_t psync_password_score(const char *cpassword){
  uint64_t score, oscore, num;
  char unsigned *lpwd, *ldpwd, *password;
  size_t plen, nlen;
  char ch;
  plen=strlen(cpassword);
  password=(unsigned char *)cpassword;
  score=1;
  // trailing ! is too common
  while (plen && password[plen-1]=='!'){
    mul_score(2);
    plen--;
  }
  // trailing 1 is too common
  if (plen && password[plen-1]=='1'){
    nlen=0;
    do {
      mul_score(2);
      plen--;
      nlen++;
    } while (plen && password[plen-1]=='1');
    while (nlen>=2){
      nlen/=2;
      score=uint_sqrt(score);
    }
  }
  ch=0;
  // if punctuation is in the end, we give it a low score
  while (plen && is_punct(password[plen-1])){
    plen--;
    if (password[plen]==ch)
      mul_score(2);
    else
      mul_score(10);
  }
  if (plen && isdigit(password[plen-1])){
    // number in the end, low score
    num=0;
    nlen=0;
    do {
      plen--;
      num=num*10+password[plen]-'0';
      nlen++;
    } while (plen && isdigit(password[plen-1]));
    mul_score(trailing_num_score(num, nlen, password+plen));
    // check for punctuation again
    while (plen && is_punct(password[plen-1])){
      plen--;
      if (password[plen]==ch)
        mul_score(2);
      else
        mul_score(10);
    }
  }
  if (!plen)
    return score;
  lpwd=psync_new_cnt(unsigned char, plen);
  ldpwd=psync_new_cnt(unsigned char, plen);
  for (nlen=0; nlen<plen; nlen++){
    lpwd[nlen]=tolower(password[nlen]);
    if (lpwd[nlen]=='0')
      ldpwd[nlen]='o';
    else if (lpwd[nlen]=='1')
      ldpwd[nlen]='i';
    else if (lpwd[nlen]=='3')
      ldpwd[nlen]='e';
    else if (lpwd[nlen]=='4')
      ldpwd[nlen]='a';
    else if (lpwd[nlen]=='5')
      ldpwd[nlen]='s';
    else if (lpwd[nlen]=='7')
      ldpwd[nlen]='t';
    else if (lpwd[nlen]=='$')
      ldpwd[nlen]='s';
    else if (lpwd[nlen]=='@')
      ldpwd[nlen]='a';
    else if (lpwd[nlen]=='!')
      ldpwd[nlen]='l';
    else
      ldpwd[nlen]=lpwd[nlen];
  }
  num=score_variants(password, lpwd, ldpwd, plen);
  psync_ssl_memclean(lpwd, plen);
  psync_ssl_memclean(ldpwd, plen);
  psync_free(lpwd);
  psync_free(ldpwd);
  mul_score(num);
  return score;
}
