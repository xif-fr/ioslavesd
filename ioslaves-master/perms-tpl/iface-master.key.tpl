/* For network simple management interfaces.
   Start/stop services, open/close ports, and status/log operations are allowed. */

allow_by_default: false;
allowed_ops: {
	a : {	// Service start
		*default* : "true";
	};
	o : {	// Service stop
		*default* : "true";
	};
	p : {};	// Open port
	c : {};	// Close port
	h : {};	// Log history
	L : {}; // Async log
	S : {};	// Status pool
};
denied_ops: [];