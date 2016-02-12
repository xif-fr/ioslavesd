/**********************************************************\
 *                  ioslaves : ioslavesd
 *                   UPnP port mapping
 * *********************************************************
 * Copyright © Félix Faisant 2013-2016. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// General
#include "main.h"
using namespace xlog;
#include <xifutils/cxx.hpp>
#include <xifutils/intstr.hpp>
#include <fcntl.h>

	// Time
inline uint64_t tm2us (timeval tv) { return tv.tv_sec*1000000+tv.tv_usec; }
inline uint64_t tmdiff (timeval tv1, timeval tv2) { return (tv1.tv_sec-tv2.tv_sec)*1000000 + (tv1.tv_usec-tv2.tv_usec); }

	// Vars
bool enable_upnp = true;
time_t ports_reopen_interval = 0;
bool ioslavesd_listening_port_open = false;
bool ports_reopen_justafter = false;
bool upnp_cache_deviceurl = false;
time_t ports_check_interval = 0;

	// miniUPnP
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/miniwget.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>
#define UPNP_DISCOVER_MAX_DELAY_MS 2000
#define UPNP_DISCOVER_INTERFACE NULL
#define UPNP_DISCOVER_IP_MULTICAST_TTL 1

	// Don't re-discover each time : caching datas
#define UPNP_CACHE_FILE IOSLAVESD_RUN_FILES"/upnp_url.cache"
#define UPNP_URL_MIN_SZ 16
UPNPUrls upnp_device_url;
IGDdatas upnp_device_data;
char upnp_lanIP[16];
time_t last_init = 0;

void ioslaves::upnpInit () {
	try {
		if (last_init != 0) 
			FreeUPNPUrls(&upnp_device_url);
		int r; ssize_t rs;
		fd_t f = -1;
			// Skip discover process
		if (upnp_cache_deviceurl) {
			off_t sz;
			r = ::access(UPNP_CACHE_FILE, W_OK);
			if (r == -1) { asroot_block();
				fd_t f = ::open(UPNP_CACHE_FILE, O_RDWR|O_CREAT, 0644);
				if (f == -1) {
					__log__(log_lvl::WARNING, "UPnP", logstream << "Failed to create UPnP URL cache file : " << ::strerror(errno));
					goto _abort_cache;
				}
				if (ioslaves_user_id != 0) 
					r = ::fchown(f, (uid_t)ioslaves_user_id, (gid_t)ioslaves_group_id);
				::close(f);
			}
			f = ::open(UPNP_CACHE_FILE, O_RDWR);
			if (f == -1) {
				__log__(log_lvl::WARNING, "UPnP", logstream << "Failed to open UPnP URL cache file : " << ::strerror(errno));
				goto _abort_cache;
			}
			sz = (off_t)::lseek(f, 0, SEEK_END);
			if (sz >= UPNP_URL_MIN_SZ) {
				::lseek(f, 0, SEEK_SET);
				char* url_str = new char[sz+1];
				RAII_AT_END_L( delete[] url_str );
				rs = ::read(f, url_str, (size_t)sz);
				if (rs != sz) 
					goto _abort_cache;
				url_str[sz] = '\0';
				for (size_t i = 0; i < (size_t)sz; i++) 
					if (url_str[i] == '\n') { url_str[sz] = '\0'; break; }
				r = UPNP_GetIGDFromUrl(url_str, 
				                       &upnp_device_url, &upnp_device_data, 
				                       upnp_lanIP, (size_t)16);
				if (r == 1) {
					__log__(log_lvl::LOG, "UPnP", logstream << "Got IGD URL in cache", LOG_DEBUG);
					last_init = ::iosl_time();
					::close(f);
					return;
				}
			}
		_abort_cache:;
		}
		RAII_AT_END({ if (f != -1) ::close(f); });
			// Search for UPnP devices on the network
		UPNPDev* dev_list = upnpDiscoverAll(UPNP_DISCOVER_MAX_DELAY_MS, 
		                                    UPNP_DISCOVER_INTERFACE, NULL, UPNP_LOCAL_PORT_SAME, false, UPNP_DISCOVER_IP_MULTICAST_TTL, 
		                                    &r);
		if (dev_list == NULL) {
			freeUPNPDevlist(dev_list);
			throw ioslaves::upnpError("No UPnP Device found on the network");
		}
		for (UPNPDev* dev = dev_list; dev != NULL; dev = dev->pNext) {
			int xml_descr_sz = 0, status_code = -1;
			const char* xml_descr = (char*)miniwget_getaddr(dev->descURL, &xml_descr_sz,
			                                                upnp_lanIP, sizeof(upnp_lanIP),
			                                                dev->scope_id, &status_code);
			if (status_code != 200 or xml_descr == NULL or xml_descr_sz == 0) {
				__log__(log_lvl::OOPS, "UPnP", logstream << "Error with UPnP device '" << dev->descURL << "'");
				continue;
			}
			::memset(&upnp_device_data, 0x0, sizeof(struct IGDdatas));
			parserootdesc(xml_descr, xml_descr_sz, 
			              &upnp_device_data);
			::free((void*)xml_descr);
			__log__(log_lvl::LOG, "UPnP", logstream << "UPnP device '" << dev->descURL << "' : " << upnp_device_data.CIF.servicetype);
			if (NULL != ::strstr(upnp_device_data.CIF.servicetype, "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:")) {
				::memset(&upnp_device_url, 0x0, sizeof(struct UPNPUrls));
				GetUPNPUrls(&upnp_device_url, 
				            &upnp_device_data, 
				            dev->descURL, dev->scope_id);
				bool igd_connected = UPNPIGD_IsConnected(&upnp_device_url, 
				                                         &upnp_device_data);
				if (igd_connected) {
					__log__(log_lvl::DONE, "UPnP", logstream << "Ok, we choose UPnP IGD " << dev->descURL);
					freeUPNPDevlist(dev_list);
					goto _ok;
				}
			}
		}
		freeUPNPDevlist(dev_list);
		throw ioslaves::upnpError("No valid UPnP IGD found");
	_ok:
		if (f != -1) {
			::ftruncate(f, (size_t)0);
			::lseek(f, (off_t)0, SEEK_SET);
			rs = ::write(f, upnp_device_url.rootdescURL, ::strlen(upnp_device_url.rootdescURL));
		}
		last_init = ::iosl_time();
	} catch (ioslaves::upnpError& upnperr) {
		__log__(log_lvl::ERROR, "UPnP", logstream << "UPnP init : " << upnperr.what());
		throw;
	}
}
inline void upnpRefreshInit () {
	if ((::iosl_time()-last_init) > 120) 
		ioslaves::upnpInit();
}

	/// Private impl functions
void upnp_ports_open (ioslaves::upnpPort& p, bool silent);
void upnp_ports_close (ioslaves::upnpPort p, bool silent);
bool upnp_port_check (in_port_t p_ext_port, ioslaves::upnpPort::proto p_proto);

void upnp_ports_open (ioslaves::upnpPort& p, bool silent) {
	if (p.p_range_sz == 0) throw std::range_error("null port range");
	if (UINT16_MAX-p.p_range_sz < p.p_int_port or UINT16_MAX-p.p_range_sz < p.p_ext_port) throw std::range_error("port range out of range");
	logl_t l;
	if (not silent) {
		if (p.p_range_sz == 1)
			__log__(log_lvl::LOG, "UPnP", logstream << "Redirecting external port " << (char)p.p_proto << p.p_ext_port << " to local port " << p.p_int_port << " with descr : \"" << p.p_descr << "\"...", LOG_WAIT, &l);
		else 
			__log__(log_lvl::LOG, "UPnP", logstream << "Redirecting external ports " << (char)p.p_proto << p.p_ext_port << '-' << p.p_ext_port+p.p_range_sz-1 << " to local ports " << p.p_int_port << '-' << p.p_int_port+p.p_range_sz-1 << " with descr : \"" << p.p_descr << "\"...", LOG_WAIT, &l);
	}
	upnpRefreshInit();
	uint16_t i;
	try {
		errno_autoreset_handle();
		int r;
			// Open port on the IGD
		for (i = 0; i < p.p_range_sz; i++) {
			std::string e_port = ::ixtoa(p.p_ext_port+i);
			std::string i_port = ::ixtoa(p.p_int_port+i);
			const char* proto = (p.p_proto == ioslaves::upnpPort::TCP) ? "TCP" : "UDP";
			r = UPNP_AddPortMapping(upnp_device_url.controlURL, upnp_device_data.first.servicetype, e_port.c_str(), i_port.c_str(), upnp_lanIP, p.p_descr.c_str(), proto, NULL, NULL);
			if (r != UPNPCOMMAND_SUCCESS) {
				errno = r;
				throw ioslaves::upnpError(logstream << "Failed to add port redirection : " << strupnperror(r) << logstr, r);
			}
		}
			// Verify if the first port of the range is opened
		bool ok = upnp_port_check(p.p_ext_port, p.p_proto);
		if (not ok) 
			throw ioslaves::upnpError("Failed to add port redirection : verification failed");
		p._is_verifiable = true;
	} catch (ioslaves::upnpError& upnperr) {
		if (not upnperr.fatal and p.p_range_sz == 1) {
			p._is_verifiable = false;
			if (not silent)
				__log__(log_lvl::WARNING, "UPnP", upnperr.what());
		} else {
			if (not silent)
				__log__(log_lvl::ERROR, "UPnP", upnperr.what());
			if (i != 0) 
				upnp_ports_close(ioslaves::upnpPort({p.p_ext_port, p.p_proto, p.p_int_port, i}), true);
		}
		throw;
	}
		// Port is successfully opened
	if (not silent) 
		__log__(log_lvl::DONE, "UPnP", logstream << "Opened", LOG_ADD, &l);
}

void upnp_ports_close (ioslaves::upnpPort p, bool silent) {
	if (p.p_range_sz == 0) throw std::range_error("null port range");
	if (UINT16_MAX-p.p_range_sz < p.p_ext_port) throw std::range_error("port range out of range");
	logl_t l;
	if (not silent) {
		if (p.p_range_sz == 1)
			__log__(log_lvl::LOG, "UPnP", logstream << "Closing external port " << (char)p.p_proto << p.p_ext_port << "...", LOG_WAIT, &l);
		else 
			__log__(log_lvl::LOG, "UPnP", logstream << "Closing external ports " << (char)p.p_proto << p.p_ext_port << '-' << p.p_ext_port+p.p_range_sz-1 << "...", LOG_WAIT, &l);
	}
	upnpRefreshInit();
	int r;
	errno_autoreset_handle();
		// Delete port mapping
	const char* proto = (p.p_proto == ioslaves::upnpPort::TCP) ? "TCP" : "UDP";
	for (size_t i = 0; i < p.p_range_sz; i++) {
		r = UPNP_DeletePortMapping(upnp_device_url.controlURL, upnp_device_data.first.servicetype, ::ixtoa(p.p_ext_port+i).c_str(), proto, NULL);
		if (r != UPNPCOMMAND_SUCCESS) {
			if (r == 714) { if (not silent) __log__(log_lvl::OOPS, "UPnP", logstream << "Failed to delete port redirection : port isn't opened"); }
			else __log__(log_lvl::OOPS, "UPnP", logstream << "Failed to delete port redirection : " << strupnperror(r));
		}
	}
		// Verify if the first port of the range is still opened
	::usleep(100000);
	try {
		if (upnp_port_check(p.p_ext_port, p.p_proto))
			__log__(log_lvl::WARNING, "UPnP", logstream << "Port " << p.p_ext_port << " is still opened after deletion !");
	} catch (ioslaves::upnpError) {}
	if (not silent) 
		__log__(log_lvl::DONE, "UPnP", "Closed", LOG_ADD, &l);
}

bool upnp_port_check (in_port_t p_ext_port, ioslaves::upnpPort::proto p_prot) {
	errno_autoreset_handle();
	upnpRefreshInit();
	int r;
		// Verify if port is opened and belongs to us
	std::string e_port = ::ixtoa(p_ext_port);
	char verif_int_port[6], verif_int_ip[16], verif_duration[16], verif_enabled[4];
	const char* proto = (p_prot == ioslaves::upnpPort::TCP) ? "TCP" : "UDP";
	r = UPNP_GetSpecificPortMappingEntry(upnp_device_url.controlURL, upnp_device_data.first.servicetype, e_port.c_str(), proto, NULL, verif_int_ip, verif_int_port, NULL, verif_enabled, verif_duration);
	if (r == 714) 
		return false;
	if (r != UPNPCOMMAND_SUCCESS) 
		throw ioslaves::upnpError(logstream << "Failed to verify port status : " << strupnperror(r) << logstr, r, false);
	if (_S(verif_int_ip) != _S(upnp_lanIP)) 
		throw ioslaves::upnpError(logstream << "Checking for port status : Port " << e_port << " doesn't belong to us, but to " << verif_int_ip << logstr, -1, false);
	return true;
}

	/// Port table
std::vector<ioslaves::upnpPort> ports_to_reopen;
pthread_mutex_t upnp_map_mutex = PTHREAD_MUTEX_INITIALIZER;

	// Check if port exists in table. mutex must be locked.
inline bool ports_table_exist (ioslaves::upnpPort& p) {
	for (ioslaves::upnpPort port : ports_to_reopen) {
		if (port.p_proto == p.p_proto and port.p_ext_port == p.p_ext_port and port.p_range_sz == p.p_range_sz) 
			return true;
	}
	return false;
}
	// Check if ports ranges are colliding in table. mutex must be locked.
inline bool ports_table_check_collision (in_port_t p_ext_port, uint16_t p_range_sz, ioslaves::upnpPort::proto proto) {
	for (ioslaves::upnpPort port : ports_to_reopen) {
		if (port.p_proto == proto) {
			if (port.p_ext_port <= p_ext_port and p_ext_port < port.p_ext_port+port.p_range_sz) return true;
			if (port.p_ext_port <= p_ext_port+p_range_sz-1 and p_ext_port+p_range_sz-1 < port.p_ext_port+port.p_range_sz) return true;
			if (p_ext_port <= port.p_ext_port and port.p_ext_port < p_ext_port+p_range_sz) return true;
			if (p_ext_port <= port.p_ext_port+port.p_range_sz-1 and port.p_ext_port+port.p_range_sz-1 < p_ext_port+p_range_sz) return true;
		}
	}
	return false;
}
inline void port_verify_range_validity (in_port_t ext_port, uint16_t range_sz) {
	if (range_sz == 0) throw std::range_error("null port range");
	if (UINT16_MAX-range_sz < ext_port) throw std::range_error("port range out of range");
}

	// Add a port into refresh ports table with time, after port opening. mutex must be locked.
inline void ports_table_add (ioslaves::upnpPort p) {
	timeval lastopentime; ::gettimeofday(&lastopentime, NULL);
	p._lastopen = lastopentime;
	ports_to_reopen.push_back(p);
}
	// Delete a port from refresh ports table. mutex must be locked. (impossible to have 2 ports range with same start ext_port)
inline void ports_table_del (in_port_t p_ext_port, ioslaves::upnpPort::proto p_proto) {
	for (auto it = ports_to_reopen.begin(); it != ports_to_reopen.end(); it++) 
		if (it->p_ext_port == p_ext_port and it->p_proto == p_proto) { ports_to_reopen.erase(it); return; }
}

	/// Reopeing ports
	// Scan ports in refresh ports table and reopen port if needed
	// Port range on "reopen_justafter" gateways let too big closed-port delays. Don't use them on this case
void ioslaves::upnpReopen () {
	static time_t unreachable = 0;
	if (unreachable != 0) {
		try {
			upnpInit();
			__log__(log_lvl::IMPORTANT, "UPnP", logstream << "Retook contact with UPnP IGD, after " << ::time(NULL)-unreachable << "s !");
			unreachable = 0;
		} catch (...) {
			if (::time(NULL)%10 == 0)
				__log__(log_lvl::FATAL, "UPnP", logstream << "IGD is unreachable for " << ::time(NULL)-unreachable << "s !");
			return;
		}
	}
	pthread_mutex_handle_lock(upnp_map_mutex);
	bool failed = false;
	logl_t l;
	for (size_t i = 0; i < ports_to_reopen.size(); i++) {
		ioslaves::upnpPort& port = ports_to_reopen[i];
		bool reopening = false;
		try {
			timeval before; ::gettimeofday(&before, NULL);
			time_t diff = tmdiff(before, port._lastopen)/1000000;
			if (port._is_verifiable) {
				if ((ports_reopen_interval and diff > ports_reopen_interval-10) or (ports_check_interval and ::time(NULL)%ports_check_interval == 0)) {
					if (not upnp_port_check(port.p_ext_port, port.p_proto)) {
						__log__(log_lvl::LOG, "UPnP", logstream << "Reopening just closed port '" << port.p_descr << "' after " << diff << "s...", LOG_WAIT, &l);
						reopening = true;
						upnp_ports_open(port, true);
						::gettimeofday(&port._lastopen, NULL);
						__log__(log_lvl::DONE, "UPnP", "Done", LOG_ADD, &l);
					}
				}
			} else {
				if (ports_reopen_interval and diff >= ports_reopen_interval) {
					reopening = true;
					__log__(log_lvl::LOG, "UPnP", logstream << "Trying to reopen port '" << port.p_descr << "' after " << diff << "s...", LOG_WAIT, &l);
					log_lvl done_lvl = log_lvl::DONE;
					try {
						upnp_ports_open(port, true);
					} catch (ioslaves::upnpError& upnperr) { if (upnperr.fatal) throw; done_lvl = log_lvl::WARNING; }
					::gettimeofday(&port._lastopen, NULL);
					__log__(done_lvl, "UPnP", "Done", LOG_ADD|LOG_WAIT, &l);
					done_lvl = log_lvl::DONE;
					try {
						upnp_ports_open(port, true);
					} catch (ioslaves::upnpError& upnperr) { if (upnperr.fatal) throw; done_lvl = log_lvl::WARNING; }
					__log__(done_lvl, "UPnP", "Done²", LOG_ADD, &l);
				}
			}
		} catch (ioslaves::upnpError& ue) {
			__log__(log_lvl::WARNING, "UPnP", logstream << "UPnP error while " << (reopening?"reopening":"checking") << " port : " << ue.what());
			if (failed) { 
				__log__(log_lvl::FATAL, "UPnP", "Ports refresh failed for the second time !");
				return;
			}
			failed = true;
			::sleep(1);
			try {
				upnpInit();
			} catch (...) { 
				__log__(log_lvl::FATAL, "UPnP", "UPnP reinitialization failed, maybe the IGD is unreachable !");
				unreachable = ::time(NULL);
				return;
			}
			i--; continue;
		}
	}
}

	/// API services interface

	// Opening function for API services
ioslaves::answer_code ioslaves::api::open_port (in_port_t ext_port, bool is_tcp, in_port_t int_port, uint16_t range_sz, std::string descr) noexcept {
	if (not enable_upnp) return ioslaves::answer_code::OK;
	pthread_mutex_handle_lock(upnp_map_mutex);
	ioslaves::upnpPort::proto proto = is_tcp ? ioslaves::upnpPort::TCP : ioslaves::upnpPort::UDP;
	ioslaves::upnpPort p = {ext_port, proto, int_port, range_sz, descr};
	try {
		if (ports_table_check_collision(ext_port, range_sz, proto))
			return ioslaves::answer_code::EXISTS;
		upnp_ports_open(p, false);
	} catch (ioslaves::upnpError& upnperr) {
		errno = upnperr.ret;
		if (upnperr.fatal)
			return ioslaves::answer_code::UPNP_ERROR;
	}
	ports_table_add(p);
	return ioslaves::answer_code::OK;
}

	// Closing function for API services
void ioslaves::api::close_port (in_port_t ext_port, uint16_t range_sz, bool is_tcp) noexcept {
	if (not enable_upnp) return;
	pthread_mutex_handle_lock(upnp_map_mutex);
	ioslaves::upnpPort::proto proto = is_tcp ? ioslaves::upnpPort::TCP : ioslaves::upnpPort::UDP;
	ports_table_del(ext_port, proto);
	try {
		upnp_ports_close(ioslaves::upnpPort({ext_port, proto, ext_port, range_sz}), false);
	} catch (ioslaves::upnpError& eu) {}
}

	/// ioslaves interface, aware of enable_upnp

void ioslaves::upnpOpenPort (upnpPort p) {
	port_verify_range_validity(p.p_ext_port, p.p_range_sz);
	pthread_mutex_handle_lock(upnp_map_mutex);
	if (ports_table_check_collision(p.p_ext_port, p.p_range_sz, p.p_proto)) 
		throw ioslaves::upnpError("Can't open : Port collision in table !", -1, true);
	try {
		upnp_ports_open(p, false);
		ports_table_add(p);
	} catch (ioslaves::upnpError& upnperr) {
		if (not upnperr.fatal) 
			ports_table_add(p);
		throw;
	}
}

void ioslaves::upnpClosePort (ioslaves::upnpPort p) {
	port_verify_range_validity(p.p_ext_port, p.p_range_sz);
	pthread_mutex_handle_lock(upnp_map_mutex);
	if (not ports_table_exist(p)) 
		throw ioslaves::upnpError("Can't close : Port not found in table !", -1, true);
	ports_table_del(p.p_ext_port, p.p_proto);
	upnp_ports_close(p, false);
}

bool ioslaves::upnpPortRangeCollision (in_port_t ext_port, uint16_t range_sz, ioslaves::upnpPort::proto proto) {
	port_verify_range_validity(ext_port, range_sz);
	pthread_mutex_handle_lock(upnp_map_mutex);
	return ports_table_check_collision(ext_port, range_sz, proto);
}
bool ioslaves::upnpPortRangeExists (ioslaves::upnpPort p) {
	port_verify_range_validity(p.p_ext_port, p.p_range_sz);
	pthread_mutex_handle_lock(upnp_map_mutex);
	return ports_table_exist(p);
}

void ioslaves::upnpShutdown () {
	for (ioslaves::upnpPort& port : ports_to_reopen) 
		upnp_ports_close(port, false);
	ports_to_reopen.clear();
}
