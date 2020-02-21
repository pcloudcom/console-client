#include <iostream>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <iterator>
#include "pclsync_lib.h"
#include "control_tools.h"
namespace ct = control_tools;

static std::string version = "2.1.0";

int main(int argc, char **argv) {
  std::cout << "pCloud console client v."<< version << std::endl;
  std::string username;
  std::string password;
  bool daemon = false;
  bool commands = false;
  bool commands_only = false;
  bool newuser = false;
  bool passwordsw = false;
  bool save_pass = false;
  bool crypto = false;
  bool trusted_device = false;

  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("username,u", po::value<std::string>(&username), "pCloud account name")
        ("password,p", po::bool_switch(&passwordsw), "Ask pCloud account password")
        ("crypto,c",  po::bool_switch(&crypto), "Ask crypto password")
        ("passascrypto,y", po::value<std::string>(), "Use user password as crypto password also.")
        ("trusted_device,t", po::bool_switch(&trusted_device), "Trust this device.")
        ("daemonize,d", po::bool_switch(&daemon), "Daemonize the process.")
        ("commands ,o", po::bool_switch(&commands), "Parent stays alive and processes commands. ")
        ("mountpoint,m", po::value<std::string>(), "Mount point where drive to be mounted.")
        ("commands_only,k", po::bool_switch(&commands_only),"Daemon already started pass only commands")
        ("newuser,n", po::bool_switch(&newuser), "Switch if this is a new user to be registered.")
        ("savepassword,s", po::bool_switch(&save_pass), "Save password in database.")
    ;

    po::variables_map vm;        
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);
    
    if (commands_only) {
      ct::process_commands();
      exit(0);
    }
    
    for (int i = 1; i < argc;++i)
      memset(argv[i],0,strlen(argv[i]));
    if (daemon){
      strncpy(argv[0], "pCloudDriveDeamon", strlen(argv[0]));
    } else {
      strncpy(argv[0], "pCloudDrive", strlen(argv[0]));
    }
    
    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }
    
    if ((!vm.count("username"))) {
      std::cout << "Username option is required!!!"  << "\n";
      return 1;
    }
    console_client::clibrary::pclsync_lib::get_lib().set_username(username);
    
    if (passwordsw) {
      console_client::clibrary::pclsync_lib::get_lib().get_pass_from_console();
    }
    
    if (crypto) {
      console_client::clibrary::pclsync_lib::get_lib().setup_crypto_ = true;
      if (vm.count("passascrypto"))
        console_client::clibrary::pclsync_lib::get_lib().set_crypto_pass(password) ;
      else {
        std::cout << "Enter crypto password."  << "\n";
        console_client::clibrary::pclsync_lib::get_lib().get_cryptopass_from_console();
      }
    } else 
       console_client::clibrary::pclsync_lib::get_lib().setup_crypto_ = false;
    
    if (vm.count("mountpoint"))
        console_client::clibrary::pclsync_lib::get_lib().set_mount( vm["mountpoint"].as<std::string>());
    
    console_client::clibrary::pclsync_lib::get_lib().newuser_ = newuser;
    console_client::clibrary::pclsync_lib::get_lib().set_savepass(save_pass);
    console_client::clibrary::pclsync_lib::get_lib().set_daemon(daemon);
    console_client::clibrary::pclsync_lib::get_lib().set_trusted_device(trusted_device);
  }
  catch(std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
  catch(...) {
    std::cerr << "Exception of unknown type!\n";
  }

  
    if (daemon)
      ct::daemonize(commands);
    else {
      if (commands)
        std::cout << "Option commnads/o  ignored."  << "\n";
      if (!console_client::clibrary::pclsync_lib::get_lib().init())
        sleep(360000);
    }
  
  return 0;
}
