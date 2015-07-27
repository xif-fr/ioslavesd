/**********************************************************\
 *               -== Xif Network project ==-
 *                   ioslaves - slave side
 *                 Key and Perms managemant
 * *********************************************************
 * Copyright © Félix Faisant 2015. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#include "main.h"
using namespace xlog;

	// General
#include <xifutils/cxx.hpp>
#include <utility>

	// Files
#include <stdio.h>
#include <sys/stat.h>
#define private public
#include <libconfig.h++>
#undef private

std::pair<ioslaves::key_t, ioslaves::perms_t> ioslaves::load_master_key (std::string master) {
	std::string key_path = _S( IOSLAVESD_KEYS_DIR,'/',master,".key" );
	FILE* key_f = ::fopen(key_path.c_str(), "r");
	if (key_f == NULL) {
		if (errno == ENOENT) 
			throw ioslaves::req_err(answer_code::NOT_FOUND, logstream << "Key not found for master '" << master << "'");
		else 
			throw xif::sys_error("failed to open key file");
	}
	RAII_AT_END_L( ::fclose(key_f); );
	libconfig::Config key_c;
	ioslaves::key_t key;
	ioslaves::perms_t perms;
	try {
		key_c.read(key_f);
		std::string key_str = key_c.lookup("key").operator std::string();
		if (key_str.length() != 2*KEY_LEN or not ioslaves::validateHexa(key_str)) 
			throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Master '" << master << "' : invalid key");
		ioslaves::hex_to_bin(key_str, key.bin);
		const libconfig::Setting& perms_c = key_c.lookup("perms");
		perms_c.assertType(libconfig::Setting::TypeGroup);
		perms.by_default = (bool)perms_c["allow_by_default"];
		const libconfig::Setting& ok_ops_c = perms_c["allowed_ops"];
		ok_ops_c.assertType(libconfig::Setting::TypeGroup);
		for (int i = 0; i < ok_ops_c.getLength(); i++) {
			ioslaves::op_code op = (ioslaves::op_code)(ok_ops_c[i].getName()[0]);
			perms.ops[op] = ioslaves::perms_t::op_perm_t({
				.authorized = true,
				.props = std::map<std::string,std::string>()
			});
			auto& props = perms.ops[op].props;
			const libconfig::Setting& props_c = ok_ops_c[i];
			props_c.assertType(libconfig::Setting::TypeGroup);
			for (int i = 0; i < props_c.getLength(); i++) {
				std::string name = props_c[i].getName();
				std::string value = props_c[i].operator std::string();
				props.insert({ name, value });
			}
		}
		const libconfig::Setting& den_ops_c = perms_c["denied_ops"];
		den_ops_c.assertType(libconfig::Setting::TypeArray);
		for (int i = 0; i < den_ops_c.getLength(); i++) {
			ioslaves::op_code op = (ioslaves::op_code)(den_ops_c[i].operator std::string()[0]);
			perms.ops[op] = ioslaves::perms_t::op_perm_t({
				.authorized = false,
				.props = std::map<std::string,std::string>()
			});
		}
	} catch (libconfig::ConfigException& e) {
		throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Error while reading key file for master '" << master << "' : " << e.what());
	}
	return std::make_pair(key, perms);
};

void ioslaves::key_save (std::string master, ioslaves::key_t key, std::string perms_conf) {
	int r;
	std::string key_path = _S( IOSLAVESD_KEYS_DIR,'/',master,".key" );
	r = ::access(key_path.c_str(), F_OK);
	if (r != -1) 
		__log__(log_lvl::WARNING, "KEY", logstream << "Key " << key_path << " already exists !");
	std::string key_str = ioslaves::bin_to_hex(key.bin, KEY_LEN);
	std::string key_file = _S(
		"key: \"", key_str, "\";\n",
		"perms: {\n", perms_conf, "\n};\n"
	);
	fd_t key_f = ::open(key_path.c_str(), O_WRONLY|O_CREAT|O_TRUNC|O_NOFOLLOW, 0600);
	if (key_f == -1) 
		throw xif::sys_error("can't open key file");
	ssize_t rs;
	rs = ::write(key_f, key_file.c_str(), key_file.length());
	if (rs != (ssize_t)key_file.length()) {
		::close(key_f);
		throw xif::sys_error("can't write to key file");
	}
	r = ::fchmod(key_f, 0400);
	if (r == -1) {
		::close(key_f);
		throw xif::sys_error("failed to chmod key file");
	}
	::close(key_f);
	__log__(log_lvl::DONE, "KEY", logstream << "Key " << key_path << " has been added");
}

ioslaves::perms_t::op_perm_t ioslaves::perms_verify_op (const ioslaves::perms_t& perms, ioslaves::op_code op) {
	auto it = perms.ops.find(op);
	if (it == perms.ops.end())
		return ioslaves::perms_t::op_perm_t({
			.authorized = perms.by_default,
			.props = std::map<std::string,std::string>()
		});
	else 
		return it->second;
};
