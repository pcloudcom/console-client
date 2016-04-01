#include <iostream>
#include <boost/program_options.hpp>
namespace po = boost::program_options;
#include <iterator>
#include "pclsync_lib.h"
#include "control_tools.h"
namespace ct = control_tools;

static std::string version = "2.0.1";

int main(int argc, char **argv) {
  std::cout << "pCloud console client v."<< version << std::endl;
  std::string username;
  std::string password;
  bool demon = false;
  bool commands = false;
  bool commands_only = false;
  
  try {
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "produce help message")
        ("username,u", po::value<std::string>(&username), "pCloud account name")
        ("password,p", po::value<std::string>(&password), "pCloud account password")
        ("crypto,c", po::value<std::string>(), "Crypto password")
        ("passascrypto,s", po::value<std::string>(), "Use user password as crypto password also.")
        ("deamonize,d", po::bool_switch(&demon), "Demonize the process.")
        ("commands ,o", po::bool_switch(&commands), "Parent stays alive and processes command after demoziation. ")
        ("mountpoint,m", po::value<std::string>(), "Mount point where drive to be mounted.")
        ("commands_only,k", po::bool_switch(&commands_only),"Demon already started pass only commands")
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
    if (demon){
      strncpy(argv[0], "pCloudDriveDeamon", strlen(argv[0]));
    } else {
      strncpy(argv[0], "pCloudDrive", strlen(argv[0]));
    }
    
    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }
    
    if ((!vm.count("username")) || (!vm.count("password"))) {
      std::cout << "Username and password options are required!!!"  << "\n";
      return 1;
    }
    console_client::clibrary::get_lib().username_ = username;
    console_client::clibrary::get_lib().password_ = password;
    
    if ((!vm.count("crypto")) && (!vm.count("passascrypto")) ){
      console_client::clibrary::get_lib().setup_crypto_ = false;
    } else {
      console_client::clibrary::get_lib().setup_crypto_ = true;
      if (vm.count("crypto"))
        console_client::clibrary::get_lib().crypto_pass_ = vm["crypto"].as<std::string>();
      else 
        console_client::clibrary::get_lib().crypto_pass_ = password;
    }
    
    if (vm.count("mountpoint"))
        console_client::clibrary::get_lib().mount_ = vm["mountpoint"].as<std::string>();
  }
  catch(std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
  catch(...) {
    std::cerr << "Exception of unknown type!\n";
  }

  
    if (demon)
      ct::demonize(commands);
    else {
      if (!console_client::clibrary::init())
        sleep(360000);
    }
  
  return 0;
}
