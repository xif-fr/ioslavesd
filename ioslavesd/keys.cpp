/**********************************************************\
 *               -== Xif Network project ==-
 *                   ioslaves - slave side
 *                 Key and Perms managemant
 * *********************************************************
 * Copyright © Félix Faisant 2013-2014. All rights reserved
 * This software is under the GNU General Public License
 \**********************************************************/

#include "main.h"
using namespace xlog;

	// General
#include <xifutils/cxx.hpp>
#include <utility>

	// Files
#include <stdio.h>
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
		key = key_c.lookup("key").operator std::string();
		if (key.length() != IOSLAVES_KEY_SIZE or not ioslaves::validateHexa(key)) 
			throw ioslaves::req_err(answer_code::INVALID_DATA, logstream << "Master '" << master << "' : invalid key");
		const libconfig::Setting& perms_c = key_c.lookup("perms_c");
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
