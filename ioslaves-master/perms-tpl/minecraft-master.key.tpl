/* Only service starting and API service communication are allowed.
   All services are denied by default (allow_by_default=false is inherited for *default* property).
   Only access to Minecraft service is allowed */

allow_by_default: false;
allowed_ops: {
	a : {	// Service start
		minecraft : "true";
	};
	l : {	// API services
		minecraft : true;
	};
};
denied_ops: [];