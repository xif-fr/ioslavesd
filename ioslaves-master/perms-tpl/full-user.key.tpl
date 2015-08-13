/* All services, ports, and status operations are allowed.
   Access to all services is allowed with *default* = true */

allow_by_default: false;
allowed_ops: {
	a : {	// Service start
		*default* : "true";
	};
	o : {	// Service stop
		*default* : "true";
	};
	l : {	// API services
		*default* : "true";
	};
	p : {};	// Open port
	c : {};	// Close port
	h : {};	// Log history
	L : {}; // Async log
	S : {};	// Status pool
};
denied_ops: [];