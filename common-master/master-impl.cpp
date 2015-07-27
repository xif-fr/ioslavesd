/**********************************************************\
 *               -== Xif Network project ==-
 *                      ioslaves-master
 *     Implementation of some connect and auth routines
 * *********************************************************
 * Copyright © Félix Faisant 2014-2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#include "common.hpp"
#include "log.h"
using namespace xlog;
#include "master.hpp"
bool iosl_master::$leave_exceptions = false;

	// Crypto
#include <openssl/whrlpool.h>
#include <openssl/md5.h>

	// Files
#define private public
#include <libconfig.h++>
#undef private

	// Network
#include <socket++/handler/socket_client.hpp>
#include <socket++/base_inet.hpp>
#include <socket++/quickdefs.h>

	// Retrieve SRV record corresponding to slave using ldns 
in_port_t iosl_master::slave_get_port_dns (std::string slave_id) {
	in_port_t $connect_port;
	std::string record_name = _S("_ioslavesd._tcp.",slave_id,'.',XIFNET_SLAVES_DOM );
	ldns_status r;
	ldns_resolver* res;
	r = ldns_resolver_new_frm_file(&res, NULL);
	if (r != LDNS_STATUS_OK) throw ldns_error(r);
	ldns_rdf* name = ldns_dname_new_frm_str(record_name.c_str());
	ldns_pkt* pkt;
	r = ldns_resolver_query_status(&pkt, res, name, LDNS_RR_TYPE_SRV, LDNS_RR_CLASS_IN, LDNS_RD);
	ldns_rdf_free(name);
	if (r != LDNS_STATUS_OK) throw ldns_error(r);
	ldns_rr_list* entries;
	entries = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_SRV, LDNS_SECTION_ANSWER);
	if (entries == NULL) throw ldns_error(LDNS_STATUS_NO_DATA);
	ldns_rr* srv_record = entries->_rrs[0];
	if (srv_record->_rd_count != 4 or srv_record->_rdata_fields[2]->_type != LDNS_RDF_TYPE_INT16) throw ldns_error(LDNS_STATUS_INVALID_RDF_TYPE);
	$connect_port = ldns_rdf2native_int16(ldns_rr_rdf(srv_record, 2));
	ldns_rr_list_deep_free(entries);
	ldns_pkt_free(pkt);
	ldns_resolver_deep_free(res);
	return $connect_port;
}

	// Resolve and connect to a slave
socketxx::base_netsock iosl_master::slave_connect (std::string slave_id, in_port_t default_port, timeval timeout) {
	in_port_t $connect_port = default_port;
	try { // Retriving port number with SRV records
		$connect_port = iosl_master::slave_get_port_dns(slave_id);
	} catch (ldns_error&) {
		if (default_port == 0)
			throw;
	}
	socketxx::base_netsock::addr_info addr ( _s(slave_id,'.',XIFNET_SLAVES_DOM), $connect_port );
	auto sock = socketxx::end::socket_client<socketxx::base_netsock> (addr, timeout);
	sock.set_read_timeout(timeout);
	return sock;
}

	// Apply operation without authentification
void iosl_master::slave_command (socketxx::io::simple_socket<socketxx::base_netsock> sock, std::string master_id, ioslaves::op_code opp) {
	socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = sock;
	try {
		slave_sock.o_bool(true);
		slave_sock.o_str(master_id);
		slave_sock.o_bool(false); // no auth
		slave_sock.o_char((char)opp);
	} catch (socketxx::error& e) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_COMM, logstream << "Failed to communicate with slave : " << e.what());
	}
}

	// Authentification
void iosl_master::authenticate (socketxx::io::simple_socket<socketxx::base_netsock> slave_sock, std::string key_id) {
	std::string key_path = _S( IOSLAVES_MASTER_KEYS_DIR,"/",key_id,".key" );
	FILE* key_f = ::fopen(key_path.c_str(), "r");
	if (key_f == NULL) {
		if (errno == ENOENT) 
			throw master_err(EXIT_FAILURE_AUTH, logstream << "No key for '" << key_id << "'");
		else 
			throw master_err(EXIT_FAILURE_SYSERR, logstream << "Failed to open key file '" << key_path << "' : " << ::strerror(errno));
	}
	RAII_AT_END_L( ::fclose(key_f) );
	ioslaves::challenge_t challenge;
	slave_sock.i_buf(challenge.bin, CHALLENGE_LEN);
	ioslaves::hash_t answer;
	try {
		libconfig::Config key_c;
		key_c.read(key_f);
		std::string store_method = key_c.lookup("method");
		libconfig::Setting& data_c = key_c.lookup("data");
		data_c.assertType(libconfig::Setting::TypeGroup);
		if (store_method == "raw") {
			std::string key_str = data_c["key"].operator std::string();
			if (key_str.length() != 2*KEY_LEN or not ioslaves::validateHexa(key_str)) 
				throw master_err("Raw key storage : invalid key", EXIT_FAILURE_EXTERR);
			unsigned char buf [CHALLENGE_LEN+KEY_LEN];
			::memcpy(buf, challenge.bin, CHALLENGE_LEN);
			ioslaves::hex_to_bin(key_str, buf+CHALLENGE_LEN);
			::WHIRLPOOL(buf, CHALLENGE_LEN+KEY_LEN, answer.bin);
		} else {
			throw master_err(EXIT_FAILURE_AUTH, logstream << "Key storage method '" << store_method << "' is unknown and external storage methods are not enabled");
		}
	} catch (libconfig::SettingException& e) {
		throw master_err(EXIT_FAILURE_EXTERR, logstream << "Missing/bad field @" << e.getPath() << " in key file for '" << key_id << "'");
	} catch (libconfig::ConfigException& e) {
		throw master_err(EXIT_FAILURE_EXTERR, logstream << "Malformed key file for '" << key_id << "' : " << e.what());
	} catch (master_err& e) {
		throw master_err(e.ret, logstream << "Failure in key file '" << key_id << "' : " << e.what());
	}
	slave_sock.o_buf(answer.bin, HASH_LEN);
	ioslaves::answer_code o = (ioslaves::answer_code)slave_sock.i_char();
	if (o == ioslaves::answer_code::OK) 
		__log__(log_lvl::DONE, "AUTH", logstream << "Authentification with key '" << key_id << "' succeded !");
	else
		throw master_err(EXIT_FAILURE_AUTH, logstream << "Authentification failed : " << ioslaves::getAnswerCodeDescription(o));
}

	// Apply operation with authentification
void iosl_master::slave_command_auth (socketxx::io::simple_socket<socketxx::base_netsock> sock, std::string master_id, ioslaves::op_code opp, std::string key_id) {
	socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = sock;
	try {
		slave_sock.o_bool(true);
		slave_sock.o_str(master_id);
		slave_sock.o_bool(true); // auth
		iosl_master::authenticate(slave_sock, key_id);
		slave_sock.o_char((char)opp);
	} catch (socketxx::error& e) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_COMM, logstream << "Failed to communicate with slave while authenticating : " << e.what());
	}
}

	// All-in-one function that returns ready-to-use connection to an API service
socketxx::base_netsock iosl_master::slave_api_service_connect (std::string slave_id, std::string master_id, std::string api_service, timeval timeout) {
	try {
		socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = iosl_master::slave_connect(slave_id, 0, timeout);
		iosl_master::slave_command_auth(slave_sock, master_id, ioslaves::op_code::CALL_API_SERVICE, _S(master_id,'.',slave_id));
		slave_sock.o_str(api_service);
		ioslaves::answer_code answ = (ioslaves::answer_code)slave_sock.i_char();
		if (answ != ioslaves::answer_code::OK) 
			throw answ;
		return slave_sock;
	} catch (socketxx::end::client_connect_error& e) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_DOWN, logstream << "Can't connect to slave : " << e.what());
	} catch (socketxx::dns_resolve_error& e) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_CONN, logstream << "Can't resolve hostname '" << e.failed_hostname << "' !");
	} catch (iosl_master::ldns_error& e) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_DOWN, logstream << "Can't retrive port number : " << e.what());
	} catch (ioslaves::answer_code o) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_IOSL, logstream << "Failed to connect to API service : " << ioslaves::getAnswerCodeDescription(o));
	} catch (socketxx::error& e) {
		if ($leave_exceptions) throw;
		throw master_err(EXIT_FAILURE_COMM, logstream << "Communication error while connecting to slave or API service : " << e.what());
	}
}

	// Test if a slave is up
bool iosl_master::slave_test (std::string slave_id) {
	try {
		socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = iosl_master::slave_connect(slave_id, 0, timeval{0,500000});
		slave_sock.o_bool(false);
		return true;
	} catch (...) {
		return false;
	}
}
