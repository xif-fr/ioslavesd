/* Everything except key management is allowed */

allow_by_default: true;
allowed_ops: {};
denied_ops: [
	"k", // Authorize key
	"d"  // Delete key
];