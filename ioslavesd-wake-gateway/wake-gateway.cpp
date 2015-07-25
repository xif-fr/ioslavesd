/**********************************************************\
 *               -== Xif Network project ==-
 *      ioslaves API service : WoL/Wake slave Gateway
 *               `ioslaves-master --on` relay
 * *********************************************************
 * Copyright © Félix Faisant 2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// ioslaves API and commons
#define IOSLAVESD_API_SERVICE
#define IOSLAVESD_API_SERVICE_IMPL
#include "api.h"
using namespace xlog;

	// General
#include <xifutils/cxx.hpp>
#include <sstream>

	// Master
#include "master.hpp"

/** -----------------------	**/
/**        Operations   		**/
/** -----------------------	**/

	// Start service
extern "C" bool ioslapi_start (const char*) {
	__log__(log_lvl::IMPORTANT, NULL, "Slave waking up relay service started.");
	return true;
}

	// Stop service
extern "C" void ioslapi_stop (void) {
	__log__(log_lvl::IMPORTANT, NULL, "Slave waking up relay service stopped.");
}

	// We do not have childs
extern "C" bool ioslapi_got_sigchld (pid_t pid, int pid_status) {
	return false;
}

	// Nothing to say
extern "C" xif::polyvar* ioslapi_status_info () {
	xif::polyvar* info = new xif::polyvar();
	return info;
}

	// Master requests
extern "C" void ioslapi_net_client_call (socketxx::base_socket& _cli_sock, const char* masterid, ioslaves::api::api_perm_t* perms, in_addr_t ip_addr) {
	if (perms == NULL) 
		throw ioslaves::req_err(ioslaves::answer_code::NOT_AUTHORIZED, "PERMS", logstream << "Wake gateway API service requires authentification");
	
	try {
		socketxx::io::simple_socket<socketxx::base_socket> cli (_cli_sock);
		std::string slave_up = cli.i_str();
		__log__(log_lvl::IMPORTANT, "WAKE", logstream << "Master wants to wake up slave '" << slave_up << "'");
		
		time_t delay = 0;
		try {
			delay = iosl_master::slave_start(slave_up, _S("_IOSL_",ioslaves::api::slave_name));
		} catch (ioslaves::req_err& re) {
			__log__(log_lvl::ERROR, "WAKE", logstream << "Failed to wake up slave : " << re.what());
			cli.o_char((char)re.answ_code);
			return;
		} catch (std::exception& e) {
			__log__(log_lvl::ERROR, "WAKE", logstream << "Error while waking up slave : " << e.what());
			cli.o_char((char)ioslaves::answer_code::ERROR);
			return;
		}
		cli.o_char((char)ioslaves::answer_code::OK);
		cli.o_int<uint16_t>(delay);
		__log__(log_lvl::DONE, "WAKE", logstream << "Done. Announced delay : " << delay);
		
	} catch (socketxx::error& e) {
		__log__(log_lvl::NOTICE, "COMM", logstream << "Network error : " << e.what());
	}
}
