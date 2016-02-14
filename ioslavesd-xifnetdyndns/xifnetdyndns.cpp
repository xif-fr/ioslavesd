/**********************************************************\
 *            ioslaves : ioslavesd-xifnetdyndns
 * Dynamic DNS service interfacing NSD for an ioslaves network
 * *********************************************************
 * Copyright © Félix Faisant 2014-2016. All rights reserved
 * This software is under the GNU General Public License
 * *********************************************************
 * This dynamic DNS service use minimal TTLs for minimizing 
 *  the time between the PPP session on the slave modem is 
 *  renewed (with often a new IP) and the final client see the 
 *  modified IP. This can leave the door opened to DNS spoofing
 \**********************************************************/

	// ioslaves API
#define IOSLAVESD_API_SERVICE
#define IOSLAVESD_API_SERVICE_IMPL
#include "api.h"
using namespace xlog;

	// General
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>
#include <vector>
#include <list>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

	// Network
#include <socket++/io/simple_socket.hpp>
#include <socket++/base_inet.hpp>

namespace xdyndns {
	
		// Slaves dyn IPs
	
	struct slave_info_t {
		std::string slave_name;
		in_addr_t last_ip;
		struct ip_change_t { timeval when; in_addr_t new_ip; };
		std::vector<slave_info_t::ip_change_t> ip_changes;
		bool was_auth;
	};
	
	std::list<xdyndns::slave_info_t> slaves;
	
		// SRV entries in the DNS
	
	struct srv_t {
		std::string domain;
		bool with_cname_redir;
		std::string service_name;
		std::string hostname;
		std::list<xdyndns::slave_info_t>::iterator on_slave;
		bool tcp;
		in_port_t port;
	};
	
	std::list<xdyndns::srv_t> srv_entries;
	
		// A record
	
	struct a_record_t {
		std::string hostname;
		in_addr_t ip_addr;
	};
	
		// Manipulate DNS Server
	
	void NSD_zone_parser (std::string domain, const std::list<xdyndns::srv_t>* srvs, xdyndns::a_record_t* slave_ip_set);
	void NSD_reload ();
	
}

/** -----------------------	**/
/**       Operations    		**/
/** -----------------------	**/

	// Start service
extern "C" bool ioslapi_start (const char*) {
	logl_t l;
	int r;
	__log__(log_lvl::IMPORTANT, NULL, logstream << "Starting XifNet Dynamic DNS Service...", LOG_WAIT, &l);
	{ sigchild_block(); asroot_block();
		r = ::system("nsd-control status > /dev/null 2>&1");
	}
	if (r != 0) {
		__log__(log_lvl::FATAL, NULL, logstream << "NSD status check failed ($? = " << r << ")");
		return false;
	}
	__log__(log_lvl::DONE, NULL, "Sanity checks OK", LOG_ADD, &l);
	return true;
}

	// Stop service
extern "C" void ioslapi_stop (void) {
	__log__(log_lvl::IMPORTANT, NULL, logstream << "XifNet Dynamic DNS Service is saying good bye");
}

	// We do not have childs
extern "C" bool ioslapi_got_sigchld (pid_t pid, int pid_status) {
	return false;
}

extern "C" xif::polyvar* ioslapi_status_info () {
	xif::polyvar* info = new xif::polyvar(xif::polyvar::map({
		{"dyn_slaves", xdyndns::slaves.size()}
	}));
	return info;
}

extern "C" void ioslapi_net_client_call (socketxx::base_socket& _cli_sock, const char* master_id, ioslaves::api::api_perm_t* perms, in_addr_t ip_addr) {
	logl_t l;
	timeval now;
	::gettimeofday(&now, NULL);
	
	std::string slave_name = master_id;
	if (slave_name.length() < 9 or slave_name.find("_IOSL_") != 0) 
		throw ioslaves::req_err(ioslaves::answer_code::DENY, NULL, logstream << "Only special slave-as-master ID are accepted");
	slave_name = slave_name.substr(6, std::string::npos);
	
	try {
		socketxx::io::simple_socket<socketxx::base_socket> cli (_cli_sock);
		in_port_t ioslavesd_port = cli.i_int<in_port_t>();
		cli.o_int<in_addr_t>(ip_addr);
		
		/* Is the slave registered ? */
		xdyndns::slave_info_t* slave = NULL;
		std::list<xdyndns::slave_info_t>::iterator slave_it;
		for (auto it = xdyndns::slaves.begin(); it != xdyndns::slaves.end(); it++) {
			if (it->slave_name == slave_name) {
				slave = &(*it);
				slave_it = it;
				goto __slave_found;
			}
		}
		
		{ /* New slave : add it into the slave list and add srv entry */
			if (ioslavesd_port == 0) {
				__log__(log_lvl::ERROR, NULL, logstream << "Slave '" << slave_name << "' not already registered");
				cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
				return;	
			}
			__log__(log_lvl::IMPORTANT, NULL, logstream << "Registering new slave '" << slave_name << "' with IP " << socketxx::base_netsock::addr_info::addr2str(ip_addr) << "...", LOG_WAIT, &l);
			if (perms == NULL)
				__log__(log_lvl::WARNING, NULL, logstream << "Slave is not authentified !");
			xdyndns::slave_info_t new_slave;
			new_slave.slave_name = slave_name;
			new_slave.ip_changes.push_back(xdyndns::slave_info_t::ip_change_t({now,ip_addr}));
			new_slave.last_ip = ip_addr;
			new_slave.was_auth = not (perms == NULL);
			slave_it = xdyndns::slaves.insert(xdyndns::slaves.begin(), new_slave);
			xdyndns::srv_t srv_entry;
			srv_entry.on_slave = slave_it;
			srv_entry.service_name = "ioslavesd";
			srv_entry.port = ioslavesd_port;
			srv_entry.domain = XIFNETDYNDNS_DYNIP_SLAVES_DOMAIN;
			srv_entry.hostname = slave_name+'.'+srv_entry.domain;
			srv_entry.with_cname_redir = false;
			srv_entry.tcp = true;
			xdyndns::srv_entries.push_back(srv_entry);
			try {
				xdyndns::a_record_t rec = {.hostname = slave_name, ip_addr};
				xdyndns::NSD_zone_parser(XIFNETDYNDNS_DYNIP_SLAVES_DOMAIN, &xdyndns::srv_entries, &rec);
				xdyndns::NSD_reload();
			} catch (const xif::sys_error& e) {
				__log__(log_lvl::ERROR, NULL, logstream << "Failed to update DNS : " << e.what());
				cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
				return;
			}
			__log__(log_lvl::DONE, NULL, "Done !", LOG_ADD, &l);
		}
		goto __ok;
		
		/* Registered slave : check if slave IP has changed, and update the DNS if it's the case  */
	__slave_found:
		if (perms == NULL and slave->was_auth) {
			__log__(log_lvl::SEVERE, "SECURITY", logstream << "Non-authentified client tries to spoof the IP of slave '" << slave->slave_name << "' !");
			cli.o_char((char)ioslaves::answer_code::DENY);
			return;
		}
		if (slave->last_ip != ip_addr) {
			if (slave->was_auth == false and not (perms == NULL)) 
				__log__(log_lvl::SEVERE, "SECURITY", logstream << "Slave " << slave->slave_name << " now connects in an authenticated manner and IP is different. Precendent slave could be a spoofer !");
			slave->was_auth = not (perms == NULL);
			__log__(log_lvl::IMPORTANT, NULL, logstream << "IP of slave '" << slave->slave_name << "' has changed from " << socketxx::base_netsock::addr_info::addr2str(slave->last_ip) << " to " << socketxx::base_netsock::addr_info::addr2str(ip_addr), LOG_WAIT, &l);
			slave->last_ip = ip_addr;
			slave->ip_changes.push_back(xdyndns::slave_info_t::ip_change_t({now,ip_addr}));
			try {
				xdyndns::a_record_t rec = {.hostname = slave_name, ip_addr};
				xdyndns::NSD_zone_parser(XIFNETDYNDNS_DYNIP_SLAVES_DOMAIN, &xdyndns::srv_entries, &rec);
				xdyndns::NSD_reload();
			} catch (const xif::sys_error& e) {
				__log__(log_lvl::ERROR, NULL, logstream << "Failed to update DNS : " << e.what());
				cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
				return;
			}
			__log__(log_lvl::DONE, NULL, "- DNS updated", LOG_ADD, &l);
		}
		
		/* Now, handle specific SRV queries */
	__ok:
		cli.o_char((char)ioslaves::answer_code::OK);
		while ((ioslaves::answer_code)cli.i_char() == ioslaves::answer_code::WANT_SEND) {
			if (perms == NULL) {
				__log__(log_lvl::ERROR, "PERMS", logstream << "Non-authentified slave isn't allowed to register additional entries.");
				cli.o_char((char)ioslaves::answer_code::DENY);
				return;
			}
			if ((*perms)["SRV"] == false) {
				__log__(log_lvl::ERROR, "PERMS", logstream << "Slave isn't allowed to register SRV entries.");
				cli.o_char((char)ioslaves::answer_code::DENY);
				return;
			}
			bool add = cli.i_bool();
			if (add) {
				xdyndns::srv_t srv_entry;
				srv_entry.on_slave = slave_it;
				srv_entry.service_name = cli.i_str();
				srv_entry.domain = cli.i_str();
				srv_entry.hostname = cli.i_str()+'.'+srv_entry.domain;
				srv_entry.with_cname_redir = cli.i_bool();
				srv_entry.tcp = cli.i_bool();
				srv_entry.port = cli.i_int<uint16_t>();
				if (srv_entry.service_name.empty() or srv_entry.domain.empty()) {
					__log__(log_lvl::ERROR, NULL, logstream << "New SRV entry : invalid data");
					cli.o_char((char)ioslaves::answer_code::INVALID_DATA);
					return;	
				}
				__log__(log_lvl::LOG, NULL, logstream << "Adding " << srv_entry.service_name << " SRV entry for " << srv_entry.hostname << " pointing to " << slave_name << ":" << srv_entry.port << "...", LOG_WAIT, &l);
				for (auto it = xdyndns::srv_entries.begin(); it != xdyndns::srv_entries.end(); it++) {
					if (it->service_name == srv_entry.service_name and it->domain == srv_entry.domain and it->hostname == srv_entry.hostname and it->tcp == srv_entry.tcp) {
						if (it->on_slave == slave_it) {
							__log__(log_lvl::WARNING, NULL, logstream << "SRV entry for " << srv_entry.hostname << " and service '" << srv_entry.service_name << "' already exists ! Overwriting.", LOG_WAIT, &l);
							xdyndns::srv_entries.erase(it);
							break;
						} else {
							__log__(log_lvl::ERROR, NULL, logstream << "SRV entry for " << srv_entry.hostname << " and service '" << srv_entry.service_name << "' is already pointing to slave '" << it->on_slave->slave_name << "' !", LOG_WAIT, &l);
							cli.o_char((char)ioslaves::answer_code::EXISTS);
							return;
						}
					}
				}
				xdyndns::srv_entries.push_back(srv_entry);
				try {
					xdyndns::NSD_zone_parser(srv_entry.domain, &xdyndns::srv_entries, NULL);
					xdyndns::NSD_reload();
				} catch (const xif::sys_error& e) {
					__log__(log_lvl::DONE, NULL, logstream << "Failed to update DNS : " << e.what());
					cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
					return;
				}
				__log__(log_lvl::DONE, NULL, "Done !", LOG_ADD, &l);
				cli.o_char((char)ioslaves::answer_code::OK);
			} else {
				std::string service_name = cli.i_str();
				std::string domain = cli.i_str();
				std::string hostname = cli.i_str()+'.'+domain;
				bool is_tcp = cli.i_bool();
				__log__(log_lvl::LOG, NULL, logstream << "Deleting " << service_name << " SRV entry for " << hostname << " pointing to " << slave_name << "...", LOG_WAIT, &l);
				for (auto it = xdyndns::srv_entries.begin(); it != xdyndns::srv_entries.end(); it++) {
					if (it->on_slave == slave_it and it->service_name == service_name and it->domain == domain and it->hostname == hostname and it->tcp == is_tcp) {
						xdyndns::srv_entries.erase(it);
						try {
							xdyndns::NSD_zone_parser(domain, &xdyndns::srv_entries, NULL);
							xdyndns::NSD_reload();
						} catch (const xif::sys_error& e) {
							__log__(log_lvl::ERROR, NULL, logstream << "Failed to update DNS : " << e.what());
							cli.o_char((char)ioslaves::answer_code::INTERNAL_ERROR);
							return;
						}
						cli.o_char((char)ioslaves::answer_code::OK);
						__log__(log_lvl::DONE, NULL, "Done", LOG_ADD, &l);
						return;
					}
				}
				__log__(log_lvl::ERROR, NULL, "Not found !", LOG_ADD, &l);
				cli.o_char((char)ioslaves::answer_code::NOT_FOUND);
			}
		}
	} catch (const socketxx::error& e) {
		__log__(log_lvl::NOTICE, "COMM", logstream << "Network error : " << e.what());
	}
}

/** -----------------------	**/
/**  DNS Server Interface  	**/   /// Here we use NSD
/** -----------------------	**/

void xdyndns::NSD_reload () {
	errno = 0;
	int r;
	{ sigchild_block(); asroot_block();
		r = ::system("nsd-control reload > /dev/null");
	}
	if (r != 0) throw xif::sys_error("failed to reload NSD zones", (errno == 0 ? "nsd-control reload failed" : _s("system(nsd-control) failed : ",::strerror(errno))));
}

/// Zone file parser

void xdyndns::NSD_zone_parser (std::string domain, const std::list<xdyndns::srv_t>* srvs, xdyndns::a_record_t* slave_ip_set) {
	fd_t f = ::open(_s( XIFNETDYNDNS_NSD_ZONES_DIR,'/',domain,".zone" ), O_RDWR);
	if (f == INVALID_HANDLE) throw xif::sys_error("can't open zone file for modifying");
	RAII_AT_END_L( ::close(f) );
	char c;
	enum { CTX_PRE_SOA, CTX_SOA, CTX_SOA_PARTH, CTX_SOA_SERIAL, CTX_SOA_SERIAL_WRITE, CTX_WAIT_DYN, CTX_BEG_DYN, CTX_DYN_HOST, CTX_DYN_FOO, CTX_DYN_IP, CTX_DYNPART_WAIT, CTX_DYNPART_WRITE } ctx = CTX_PRE_SOA;
	size_t tok = 0;
	std::function<int(const char*)> tok_test = [&](const char* need) -> int {
		if (c == need[tok]) tok++;
		else { tok = 0; return -1; }
		if (tok == ::strlen(need)) { tok = 0; return 1; }
		else return 0;
	};
	std::string buf, this_slave;
	off_t off = 0;
	try {
		while (::read(f, &c, 1) == 1) {
			switch (ctx) {
				case CTX_PRE_SOA:
					if (tok_test("SOA") == 1) ctx = CTX_SOA;
					continue;
				case CTX_SOA:
					if (c == '(') ctx = CTX_SOA_PARTH;
					continue;
				case CTX_SOA_PARTH:
					if (c == '0') ctx = CTX_SOA_SERIAL;
					continue;
				case CTX_SOA_SERIAL:
					off--;
					if (c == ';') ctx = CTX_SOA_SERIAL_WRITE;
					else if (c != ' ') buf += c;
					continue;
				case CTX_SOA_SERIAL_WRITE: {
					size_t serial = ::atoix<size_t>(buf, IX_DEC);
					serial++;
					buf = ::ixtoa(serial);
					::lseek(f, off-1, SEEK_CUR);
					off = 0;
					if ( ::write(f, buf.c_str(), buf.length()) != (ssize_t)buf.length() ) goto __werror;
					buf.clear();
					if (slave_ip_set != NULL)
						ctx = CTX_WAIT_DYN;
					else 
						ctx = CTX_DYNPART_WAIT;
				} continue;
				case CTX_WAIT_DYN:
					if (tok_test("; Dynamic IP hosts") == 1) ctx = CTX_BEG_DYN;
					continue;
				case CTX_BEG_DYN:
					if (c == '\n') ctx = CTX_DYN_HOST;
					continue;
				case CTX_DYN_HOST:
					if (c == ' ' or c == '\t') { 
						if (buf.empty()) throw xif::sys_error("dyndns zone parse error", "empty host");
						this_slave = buf;
						buf.clear();
						ctx = CTX_DYN_FOO;
					}
					else if (c == '\n' and buf.empty()) {
						off = ::strlen("xxx.xxx.xxx.xxx")+1;
						buf = socketxx::base_netsock::addr_info::addr2str(slave_ip_set->ip_addr);
						buf = _S( slave_ip_set->hostname,"\tIN A\t",buf,std::string(off-buf.length(),' '),";\n\n; -- DYN -- ;\n" );
						::lseek(f, -1, SEEK_CUR);
						if ( ::write(f, buf.c_str(), buf.length()) != (ssize_t)buf.length() ) goto __werror;
						ctx = CTX_DYNPART_WRITE;
					}
					else buf += c;
					continue;
				case CTX_DYN_FOO:
					off = 0;
					if (isdigit(c)) ctx = CTX_DYN_IP;
					else continue;
				case CTX_DYN_IP:
					if (c == ' ') {
						if (this_slave == slave_ip_set->hostname) {
							::lseek(f, off-1, SEEK_CUR);
							off = 0;
							std::string ipstr = socketxx::base_netsock::addr_info::addr2str(slave_ip_set->ip_addr);
							if (buf.length() > ipstr.length()) 
								ipstr += std::string(buf.length()-ipstr.length(),' ');
							if ( ::write(f, ipstr.c_str(), ipstr.length()) != (ssize_t)ipstr.length() ) goto __werror;
							ctx = CTX_DYNPART_WAIT;
							continue;
						}
						buf.clear();
						::lseek(f, -1, SEEK_CUR);
						ctx = CTX_BEG_DYN;
						continue;
					}
					buf += c; off--;
					continue;
				case CTX_DYNPART_WAIT:
					if (tok_test("; -- DYN -- ;\n") == 1) ctx = CTX_DYNPART_WRITE;
					continue;
				case CTX_DYNPART_WRITE:
					::ftruncate(f, ::lseek(f, -1, SEEK_CUR)+1);
				__CTX_DYNPART_WRITE:
					bool write_header = true;
					if (srvs == NULL) 
						return;
					for (xdyndns::srv_t srv : *srvs) {
						if (srv.domain == domain and srv.with_cname_redir) {
							if (write_header) {
								buf = "\n; Dynamic CNAME entries ;\n";
								if ( ::write(f, buf.c_str(), buf.length()) != (ssize_t)buf.length() ) goto __werror;
								write_header = false;	
							}
							buf = _S( srv.hostname,".\tIN CNAME\t",srv.on_slave->slave_name,'.',XIFNETDYNDNS_DYNIP_SLAVES_DOMAIN,".\n" );
							if ( ::write(f, buf.c_str(), buf.length()) != (ssize_t)buf.length() ) goto __werror;
						}
					}
					write_header = true;
					for (xdyndns::srv_t srv : *srvs) {
						if (srv.domain == domain) {
							if (write_header) {
								buf = "\n; Dynamic SRV entries ;\n";
								if ( ::write(f, buf.c_str(), buf.length()) != (ssize_t)buf.length() ) goto __werror;
								write_header = false;	
							}
							buf = _S( "_",srv.service_name,"._",(srv.tcp?"tcp":"udp"),".",srv.hostname,". 1 IN SRV 0 100 ",::ixtoa(srv.port)," ",srv.on_slave->slave_name,'.',XIFNETDYNDNS_DYNIP_SLAVES_DOMAIN,".\n" );
							if ( ::write(f, buf.c_str(), buf.length()) != (ssize_t)buf.length() ) goto __werror;	
						}
					}
					return;
			}
		}
		if (ctx == CTX_DYNPART_WAIT) 
			goto __CTX_DYNPART_WRITE;
		throw xif::sys_error("dyndns zone parse error", (ctx < CTX_DYNPART_WAIT) ? 
																		_S("didn't reach DYNPART ctxs (ctx=",::ixtoa((int)ctx),")"):
																		"wtf, srv table not written");
	} catch (const xif::sys_error& se) {
		throw;
	} catch (const std::exception& e) {
		throw xif::sys_error("dyndns zone parse error", e.what());
	}
__werror:
	throw xif::sys_error("dyndns zone updating : can't write to file");
}
