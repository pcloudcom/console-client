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

#include <string>

struct pstatus_struct_;

namespace console_client { 
  namespace clibrary { 
    
    struct pclsync_lib
    {
      public:

      ~pclsync_lib();
      pclsync_lib();
    
      const std::string& get_username() {return username_;}
      const std::string& get_password() {return password_;}
      const std::string& get_crypto_pass() {return crypto_pass_;};
      const std::string& get_mount() {return mount_;}
      
      void set_username(const std::string& arg) { username_ = arg;}
      void set_password(const std::string& arg) { password_ = arg;}
      void set_crypto_pass(const std::string& arg) { crypto_pass_ = arg;};
      void set_mount(const std::string& arg) { mount_ = arg;}
     
      void get_pass_from_console();
      void get_cryptopass_from_console();

      static int init();//std::string& username, std::string& password, std::string* crypto_pass, int setup_crypto = 1, int usesrypto_userpass = 0);
      static pclsync_lib& get_lib();
      
      static int statrt_crypto (const char* pass);
      static int stop_crypto (const char* path);
      static int finalize (const char* path);
      
    public:
     pstatus_struct_* status_;

      std::string username_;
      std::string password_;
      std::string crypto_pass_;
      std::string mount_;
      bool was_init_;
      bool setup_crypto_;
      bool to_set_mount_;
      bool crypto_on_;
      bool newuser_;
      bool save_pass_;
      bool daemon_;
      
      static pclsync_lib g_lib;
      
    private:
      void do_get_pass_from_console(std::string& password);

    };
    
  }
}

#endif // PCLSYNC_LIB_H
