/**********************************************************\
 *               -== Xif Network project ==-
 *                      ioslaves-master
 *     Implementation of some connect and auth routines
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

	// Common
#include "common.hpp"
#include "master.hpp"
bool iosl_master::$leave_exceptions = false;

	// Files
#include <fstream>

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
		throw master_err(_S( "Failed to communicate with slave : ",e.what() ), EXIT_FAILURE_COMM);
	}
}

	// Authentification
void iosl_master::authenticate (socketxx::io::simple_socket<socketxx::base_netsock> slave_sock, std::string slave_id) {
	std::string key_path = _S( IOSLAVES_MASTER_KEYS_DIR,"/",slave_id,".key" );
	int r = ::access(key_path.c_str(), F_OK);
	if (r == -1) 
		throw master_err(_S( "No key for slave '",slave_id,"'" ), EXIT_FAILURE_ERR);
	std::string key;
	try {
		std::ifstream key_f; key_f.exceptions(std::ifstream::failbit|std::ifstream::badbit);
		key_f.open(key_path);
		key = std::string (std::istreambuf_iterator<char>(key_f),
								 std::istreambuf_iterator<char>());
	} catch (std::ifstream::failure& e) {
		throw master_err(_S( "Failed to read key file : ",e.what() ), EXIT_FAILURE_ERR);
	}
	std::string challenge = slave_sock.i_str();
	std::string answer = ioslaves::hash(challenge+key);
	slave_sock.o_str(answer);
	ioslaves::answer_code anws = 
	(ioslaves::answer_code)slave_sock.i_char();
	if (anws != ioslaves::answer_code::OK) 
		throw master_err("Authentification failed !", EXIT_FAILURE_AUTH);
}

	// Apply operation with authentification
void iosl_master::slave_command_auth (socketxx::io::simple_socket<socketxx::base_netsock> sock, std::string master_id, ioslaves::op_code opp, std::string slave_id) {
	socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = sock;
	try {
		slave_sock.o_bool(true);
		slave_sock.o_str(master_id);
		slave_sock.o_bool(true); // auth
		iosl_master::authenticate(slave_sock, slave_id);
		slave_sock.o_char((char)opp);
	} catch (socketxx::error& e) {
		if ($leave_exceptions) throw;
		throw master_err(_S( "Failed to communicate with slave while authenticating : ",e.what() ), EXIT_FAILURE_COMM);
	}
}

	// Connect to API service with authentication
void iosl_master::slave_api_service_connect (socketxx::io::simple_socket<socketxx::base_netsock> sock, std::string master_id, std::string slave_id, std::string api_service) {
	socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = sock;
	iosl_master::slave_command_auth(slave_sock, master_id, ioslaves::op_code::CALL_API_SERVICE, slave_id);
	try {
		slave_sock.o_str(api_service);
		ioslaves::answer_code answ = (ioslaves::answer_code)slave_sock.i_char();
		if (answ != ioslaves::answer_code::OK) 
			throw answ;
	} catch (socketxx::error& e) {
		if ($leave_exceptions) throw;
		throw master_err(_S( "Failed to start communication with API service : ",e.what() ), EXIT_FAILURE_COMM);
	}
}
socketxx::base_netsock iosl_master::slave_api_service_connect (std::string slave_id, std::string master_id, std::string api_service, timeval timeout) {
	try {
		socketxx::io::simple_socket<socketxx::base_netsock> slave_sock = iosl_master::slave_connect(slave_id, 0, timeout);
		iosl_master::slave_api_service_connect(slave_sock, master_id, slave_id, api_service);
		return slave_sock;
	} catch (socketxx::end::client_connect_error& e) {
		if ($leave_exceptions) throw;
		throw master_err(_S( "Can't connect to slave : ",e.what() ), EXIT_FAILURE_CONN, true);
	} catch (socketxx::dns_resolve_error& e) {
		if ($leave_exceptions) throw;
		throw master_err(_S( "Can't resolve hostname '",e.failed_hostname,"' !" ), EXIT_FAILURE_CONN);
	} catch (iosl_master::ldns_error& e) {
		if ($leave_exceptions) throw;
		throw master_err(_S( "Can't retrive port number : ",e.what() ), EXIT_FAILURE_CONN);
	} catch (socketxx::error& e) {
		if ($leave_exceptions) throw;
		throw master_err(_S( "Failed to connect to slave : ",e.what() ), EXIT_FAILURE_CONN);
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
