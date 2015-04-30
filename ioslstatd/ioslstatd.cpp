/**********************************************************\
 *                 -== Xif Network project ==-
 *                         ioslstatd
 *               ioslaves master : status deamon
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Commons
#include "common.hpp"
#include "master.hpp"
	
	// Log
#include <iostream>
#define LOG_ARROW       "\033[34;1m=> \033[0m"
#define LOG_ARROW_OK    "\033[32;1m=> \033[0m"
#define LOG_ARROW_ERR   "\033[31;1m=> \033[0m"
#define LOG_AROBASE     "\033[34m @ \033[0m"
#define LOG_AROBASE_OK  "\033[32m @ \033[0m"
#define LOG_AROBASE_ERR "\033[31m @ \033[0m"
#define NICE_WARNING    "\033[1;31m/!\\\033[0m"
#define COLOR_RED       "\033[1;31m"
#define COLOR_YELLOW    "\033[1;33m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_RESET     "\033[0m"

	// Misc
#include <stdlib.h>
#include <getopt.h>
#include <list>
#include <map>
#include <time.h>

	// Network
#include <socket++/base_inet.hpp>
#include <socket++/io/simple_socket.hpp>
#include <socket++/handler/socket_client.hpp>
#include <socket++/quickdefs.h>

	// Websockets
#include <nopoll.h>
#define WEBSOCK_PORT 29068

	// Signal
#include <signal.h>
sig_atomic_t loop = true;
void _sigend (int param);
void _sigend (int param) {
	loop = false;
}

int main (int argc, char* const argv[]) {
	
	if (argc < 2) return EXIT_FAILURE;
	std::string master_id = argv[1];
	
	::signal(SIGINT, _sigend);
	::signal(SIGTERM, _sigend);
	::signal(SIGHUP, _sigend);
	
	std::map< std::string, socketxx::io::simple_socket<socketxx::base_netsock> > slaves;
	RAII_AT_END_N(del_slaves, {
		while (slaves.size()) 
			slaves.erase(slaves.begin());
	});
	
	for (optind = 2; optind < argc; optind++) {
		std::string slave = argv[optind];
		if (ioslaves::validateSlaveName(slave)) {
			
			std::cerr << LOG_ARROW << "Connecting to slave '" << slave << "'..." << std::endl;
			
			try {
				socketxx::simple_socket_client<socketxx::base_netsock> slave_sock = iosl_master::slave_connect(slave, 0);
				iosl_master::slave_command(slave_sock, master_id, ioslaves::op_code::PERM_STATUS);
				ioslaves::answer_code answ = (ioslaves::answer_code)slave_sock.i_char();
				if (answ != ioslaves::answer_code::OK) 
					throw answ;
				slaves.insert( decltype(slaves)::value_type( slave, slave_sock ) );
				std::cerr << LOG_ARROW_OK << "Ok" << std::endl;
			} catch (ioslaves::answer_code& answ) {
				std::cerr << LOG_ARROW_ERR << "Answer code : " << (char)answ << std::endl;
			} catch (master_err& e) {
				std::cerr << LOG_ARROW_ERR << "Master error : " << e.what() << std::endl;
			} catch (socketxx::dns_resolve_error& e) {
				std::cerr << LOG_ARROW_ERR << "Can't resolve hostname '" << e.failed_hostname << "' !" << std::endl;
			} catch (iosl_master::ldns_error& e) {
				std::cerr << LOG_ARROW_ERR << "Can't retrive port number : " << e.what() << std::endl;
			} catch (socketxx::error& e) {
				std::cerr << LOG_ARROW_ERR << "Failed to connect to slave : " << e.what() << std::endl;
			}
			
			
		}
	}
	
	noPollCtx* wsctx = NULL;
	RAII_AT_END_N(ws,{
		if (wsctx != NULL) nopoll_ctx_unref(wsctx);
		nopoll_cleanup_library();
	});
	std::cerr << LOG_AROBASE << "Creating websocket on port " << WEBSOCK_PORT << "..." << std::endl;
	wsctx = nopoll_ctx_new();
	if (wsctx == NULL) {
		std::cerr << LOG_AROBASE_ERR << "Failed to create websocket context" << std::endl;
		return EXIT_FAILURE;
	}
	noPollConn* listener = nopoll_listener_new(wsctx, "0.0.0.0", ::ixtoa(WEBSOCK_PORT).c_str());
	if (not nopoll_conn_is_ok(listener)) {
		std::cerr << LOG_AROBASE_ERR << "Failed to create listening websocket" << std::endl;
		return EXIT_FAILURE;
	}
	fd_t listen_fd = nopoll_conn_socket(listener);
	
	std::list<noPollConn*> ws_clients;
	
	int r;
	fd_set set;
	FD_ZERO(&set);
	fd_t maxfd = listen_fd;
	FD_SET(listen_fd, &set);
	
	for (auto it = slaves.begin(); it != slaves.end(); it++) {
		fd_t sock = (*it).second.get_fd();
		FD_SET(sock, &set);
		if (sock > maxfd) maxfd = sock;
	}
	
	time_t last_send;
	time_t last_zerocli = 0;
	xif::polyvar aggregated = xif::polyvar::map();
	
	while (::loop) {
		
		fd_set set2 = set;
		timeval tm = ::timeval{0,10000};
		r = ::select(maxfd+1, &set2, NULL, NULL, &tm);
		
		if (r == -1) { 
			if (errno == EINTR) continue;
			throw xif::sys_error("select() failed");
		}
		else {
			time_t now = ::time(NULL);
			if (now > last_send) {
				if (ws_clients.size() == 0) {
					if (last_zerocli == 0) 
						last_zerocli = ::time(NULL);
					else if (::time(NULL) > last_zerocli+6) {
						std::cerr << "No clients since 6sec. Quit." << std::endl;
						::loop = false;
					}
				} else 
					last_zerocli = 0;
				std::cerr << "Sending to " << ws_clients.size() << " clients..." << std::endl;
				std::string json = aggregated.to_json(3);
				for (auto it = ws_clients.begin(); it != ws_clients.end();) {
					noPollConn* cli = (*it);
					int rs = nopoll_conn_send_text(cli, json.c_str(), json.length());
					if (rs != (int)json.length()) {
						std::cerr << LOG_AROBASE_ERR << "Error while writing to websocket client. Bye." << std::endl;
						auto p_it = it++; ws_clients.erase(p_it);
					} else
						++it;
				}
				last_send = now;
				continue;
			}
		}
		
		if (FD_ISSET(listen_fd, &set2)) {
			std::cerr << LOG_AROBASE << "New websocket client" << std::endl;
			noPollConn* cli = nopoll_conn_accept(wsctx, listener);
			if (cli == NULL or not nopoll_conn_is_ok(listener)) {
				nopoll_conn_close(cli);
				std::cerr << LOG_AROBASE_ERR << "Failed to accept new client" << std::endl;
				continue;
			}
			noPollMsg* msg = nopoll_conn_get_msg(cli);
			if (msg == NULL) {
				nopoll_conn_close(cli);
				std::cerr << LOG_AROBASE_ERR << "Failed to get initial message" << std::endl;
				continue;
			}
			std::string msgstr ((const char*)nopoll_msg_get_payload(msg), nopoll_msg_get_payload_size(msg));
			nopoll_msg_unref(msg);
			std::cerr << LOG_AROBASE_OK << "Welcome message : " << msgstr << std::endl;
			ws_clients.insert(ws_clients.begin(), cli);
			continue;
		}
		
		for (auto it = slaves.begin(); it != slaves.end(); it++) {
			if (FD_ISSET((*it).second.get_fd(), &set2)) {
				std::cerr << "Receiving data from slave " << (*it).first << std::endl;
				try {
					xif::polyvar info = (*it).second.i_var();
					if (info["me"].s() != (*it).first) {
						std::cerr << "Slave " << (*it).first << " : Paradoxe spatio-temporel !" << std::endl;
						break;
					}
					xif::polyvar sys = info["system"];
					aggregated[(*it).first.c_str()] = sys;
				} catch (socketxx::error& e) {
					std::cerr << LOG_ARROW_ERR << "Error while reading data from slave '" << (*it).first << "' ! Bye." << std::endl;
					aggregated[(*it).first.c_str()] = xif::polyvar();
					FD_CLR((*it).second.get_fd(), &set);
					slaves.erase(it);
				} catch (std::runtime_error& e) {
					std::cerr << "Slave " << (*it).first << " : bad data : " << e.what() << std::endl;
				}
				break;
			}
		}
		
	}
	
	for (auto it = ws_clients.begin(); it != ws_clients.end(); it++) 
		nopoll_conn_close(*it);
	nopoll_conn_close(listener);
	
	return EXIT_SUCCESS;
	
}
