/* For ioslavesd authentified access to dynamic DNS service  */

allow_by_default: false;
allowed_ops: {
	l : {	// API services
		xifnetdyndns : "true"; // Allow access to xifnetdyndns service
		xifnetdyndns*SRV : "true"; // Allow SRV entries adding
	};
};
denied_ops: [];