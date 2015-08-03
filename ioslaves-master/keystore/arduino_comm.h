enum arduino_auth_opcode {
	OP_ADD_KEY = 'k',
	OP_CHALLENGE = 'c',
	OP_DUMP_EEPROM = 'd',
	OP_ERASE_EEPROM = 'e',
};

enum arduino_auth_answ {
	OK = 'o',
	NO_MORE_SPACE = '#',
	EEPROM_ERROR = 'e',
	PASSWD_FAIL = 'w',
	NOT_FOUND = '?',
	COMM_ERROR = '@',
	ERROR = '*'
};

#define KEY_SZ 256
#define KEY_ID_MAX_SZ 32
#define CHALLENGE_SZ 256