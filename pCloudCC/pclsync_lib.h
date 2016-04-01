/*
 * Copyright (c) 2013-2015 pCloud Ltd.
 *  All rights reserved.
 * 
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of pCloud Ltd nor the
 *        names of its contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 * 
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL pCloud Ltd BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PCLSYNC_LIB_H
#define PCLSYNC_LIB_H

#include <auto_ptr.h>
#include <iosfwd>
#include <string>
#include <boost/shared_ptr.hpp>
#include <iostream>

struct pstatus_struct_;

namespace console_client { 
  namespace clibrary { 
    
    struct pclsync_lib
    {
      public:

      ~pclsync_lib();
      pclsync_lib();
    
      std::ostream& get_out() {
        if (out_)
          return *out_;
        else
          return std::cout;
      }
      const std::string& get_username() {return username_;}
      const std::string& get_password() {return password_;}
      const std::string& get_crypto_pass() {return crypto_pass_;};
      const std::string& get_mount() {return mount_;}

    
    public:
      std::auto_ptr<pstatus_struct_> status_;
      
      boost::shared_ptr<std::ostream> out_;
      std::string username_;
      std::string password_;
      std::string crypto_pass_;
      std::string mount_;
      bool was_init_;
      bool setup_crypto_;
      bool to_set_mount_;
      bool crypto_on_;
    };
    
    int init();//std::string& username, std::string& password, std::string* crypto_pass, int setup_crypto = 1, int usesrypto_userpass = 0);
    
    pclsync_lib& get_lib();
    
  }
}

#endif // PCLSYNC_LIB_H
