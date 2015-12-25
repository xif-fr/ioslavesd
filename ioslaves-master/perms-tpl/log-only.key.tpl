/* Only log and status access */

allow_by_default: false;
allowed_ops: {
	h : {};	// Log history
	L : {}; // Async log
	S : {};	// Status pool
};
denied_ops: [];