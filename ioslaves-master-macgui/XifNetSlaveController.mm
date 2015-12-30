#import "XifNetSlaveController.h"
#import "XifNetAppDelegate.h"
#import "macgui-common.h"

	// Common master
#include "log.h"
using namespace xlog;
#include "common.hpp"
#include "master.hpp"

	// Global auth mutex
pthread_mutex_t auth_mutex = PTHREAD_MUTEX_INITIALIZER;

	// Misc
#include <stdexcept>
#include <xifutils/cxx.hpp>
#include <xifutils/objcxx.hh>
#include <sys/time.h>

	// Files
#include <unistd.h>
#include <sys/stat.h>

	// Arduino reuse connection
extern "C" fd_t arduino_auth_reuse_fd = 0;

	// Network
#include <socket++/base_inet.hpp>
#include <socket++/io/simple_socket.hpp>
#include <socket++/handler/socket_server.hpp>

	// Log colors
#define MakeLogAttrStr(str, ...) \
	([] () -> NSAttributedString* { \
		@autoreleasepool { \
			return [[NSAttributedString alloc] initWithString:str attributes:__VA_ARGS__]; \
		} \
	})()
inline NSColor* MakeLogAttrColor (uint8_t r, uint8_t v, uint8_t b) {
	return [NSColor colorWithCalibratedRed:(r/255.f) green:(v/255.f) blue:(b/255.f) alpha:1.f];
}
inline NSFont* MakeLogAttrFont (NSString* fontName, CGFloat size, NSFontTraitMask traits = 0) {
	NSFontManager* fontManager = [[NSFontManager alloc] init];
	NSFont* logFont = [NSFont fontWithName:fontName size:size];
	logFont = [fontManager convertFont:logFont toHaveTrait:traits];
	[fontManager release];
	return logFont;
}
NSAttributedString* log_lvl_strs[] = {
	[(int)log_lvl::FATAL] = MakeLogAttrStr(@"[FATAL]", @{ 
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(252,57,31),
		NSUnderlineStyleAttributeName : [NSNumber numberWithInt:NSUnderlineStyleSingle]
	}),
	[(int)log_lvl::ERROR] = MakeLogAttrStr(@"[ERROR]", @{ 
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(252,57,31), 
	}),
	[(int)log_lvl::OOPS] = MakeLogAttrStr(@"[OOPS]", @{ 
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11),
		NSForegroundColorAttributeName : MakeLogAttrColor(198,54,33) 
	}),
	[(int)log_lvl::SEVERE] = MakeLogAttrStr(@"[SEVERE]", @{ 
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(198,24,111) 
	}),
	[(int)log_lvl::WARNING] = MakeLogAttrStr(@"[WARNING]", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait|NSFontItalicTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(255,255,80) 
	}),
	[(int)log_lvl::NOTICE] = MakeLogAttrStr(@"[NOTICE]", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(255,255,255),
		NSUnderlineStyleAttributeName : [NSNumber numberWithInt:NSUnderlineStyleSingle]
	}),
	[(int)log_lvl::LOG] = MakeLogAttrStr(@"[LOG]", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(255,255,255)
	}),
	[(int)log_lvl::IMPORTANT] = MakeLogAttrStr(@"[IMP]", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait|NSFontItalicTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(20,240,240)
	}),
	[(int)log_lvl::MAJOR] = MakeLogAttrStr(@"[MAJOR]", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(88,51,255),
	}),
	[(int)log_lvl::DONE] = MakeLogAttrStr(@"[DONE]", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11),
		NSForegroundColorAttributeName : MakeLogAttrColor(37,188,36) 
	}),
};
NSAttributedString* log_master_strs[] = {
	[(int)log_lvl::FATAL] = MakeLogAttrStr(@"=>", @{ 
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(252,57,31),
	}),
	[(int)log_lvl::ERROR ... (int)log_lvl::SEVERE] = log_master_strs[(int)log_lvl::FATAL],
	[(int)log_lvl::WARNING] = MakeLogAttrStr(@"/!\\", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(255,255,80) 
	}),
	[(int)log_lvl::NOTICE] = MakeLogAttrStr(@"•", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(255,255,255),
	}),
	[(int)log_lvl::LOG] = log_master_strs[(int)log_lvl::NOTICE],
	[(int)log_lvl::IMPORTANT] = MakeLogAttrStr(@"=>", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(88,51,255),
	}),
	[(int)log_lvl::MAJOR] = log_master_strs[(int)log_lvl::IMPORTANT],
	[(int)log_lvl::DONE] = MakeLogAttrStr(@"=>", @{
		NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontBoldTrait),
		NSForegroundColorAttributeName : MakeLogAttrColor(49,231,34) 
	}),
};
#define AUTO_SCROLL_TRIGGER 50

	// Slave views controller
@implementation XifNetSlaveController

- (NSView*)slaveMenuView {
	return slaveMenuView;
}
- (void)menuWillOpen {
	if (isConnecting)
		[slaveConnectIndicator performSelector:@selector(startAnimation:)
		                            withObject:self
		                            afterDelay:0.0
		                               inModes:[NSArray arrayWithObject:NSEventTrackingRunLoopMode]];
}

- (id)initWithSlaveID:(std::string)slaveId fullName:(NSString*)fullName {
	self = [super init];
	if (self) {
		stopFD = INVALID_HANDLE;
		slaveID = slaveId;
		slaveFullName = [fullName retain];
		[NSBundle loadNibNamed:@"SlaveViews" owner:self];
		[slaveNameLabel setStringValue:slaveFullName];
		[slaveStatusImage setHidden:YES];
		isConnecting = false;
		isConnected = false;
		[slaveReconnectButton setEnabled:NO];
		[slaveReconnectButton setTarget:self]; [slaveReconnectButton setAction:@selector(reconnect:)];
		[slaveSSHButton setTarget:self]; [slaveSSHButton setAction:@selector(connectSSH:)];
		[slaveSSHFSButton setTarget:self]; [slaveSSHFSButton setAction:@selector(connectSSHFS:)];
		[clearLogButton setTarget:self]; [clearLogButton setAction:@selector(clearLog:)];
		lastLogSeen = ::time(NULL);
		[self logSeen];
		NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
		NSDictionary* prefsSlaves = [prefs dictionaryForKey:@"slaves"];
		if (prefsSlaves == nil) {
			prefsSlaves = [NSDictionary dictionary];
			[prefs setObject:prefsSlaves forKey:@"slaves"];
			[prefs synchronize];
		}
		NSDictionary* slavePrefs = [prefsSlaves objectForKey:[NSString stringWithStdString:self->slaveID]];
		if (slavePrefs == nil) {
			slavePrefs = [NSDictionary dictionaryWithObjectsAndKeys:[NSDictionary dictionary], @"ssh", 
			                                                        nil];
			prefsSlaves = [NSMutableDictionary dictionaryWithDictionary:prefsSlaves];
			[prefsSlaves setValue:slavePrefs forKey:[NSString stringWithStdString:self->slaveID]];
			[prefs setObject:prefsSlaves forKey:@"slaves"];
			[prefs synchronize];
		}
		[self loadSshPresets];
	}
	return self;
}

- (void)loadSshPresets {
	NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
	NSDictionary* prefsSlaves = [prefs dictionaryForKey:@"slaves"];
	NSDictionary* slavePrefs = [prefsSlaves objectForKey:[NSString stringWithStdString:self->slaveID]];
	NSArray* sshPresets = [slavePrefs objectForKey:@"ssh"];
	[slaveSshPresets setSegmentCount:[sshPresets count]+1];
	[slaveSshPresets setLabel:@"+" forSegment:0];
	if ([sshPresets count] != 0)
		[slaveSshPresets setWidth:25.f forSegment:0];
	CGFloat sshPresetWidth = ([slaveSshPresets frame].size.width - 32.f) / [sshPresets count];
	for (NSUInteger i = 0; i < [sshPresets count]; i++) {
		[slaveSshPresets setLabel:[[sshPresets objectAtIndex:i] objectForKey:@"name"] forSegment:i+1];
		[slaveSshPresets setWidth:sshPresetWidth forSegment:i+1];
	}
}

- (NSDictionary*)sshGetPreset {
	if ([slaveSshPresets selectedSegment] == -1) 
		return nil;
	if ([slaveSshPresets selectedSegment] == 0) {
		[self->subMenu cancelTracking];
		::dispatch_async(dispatch_get_main_queue(), ^{ std::function<void()> newPresetBlock = [&] () {
			NSAlert* alert = [NSAlert alertWithMessageText:@"New SSH preset"
			                                 defaultButton:@"OK"
			                               alternateButton:@"Cancel"
			                                   otherButton:nil
			                     informativeTextWithFormat:@"Please enter valid settings for a new SSH/SSHFS preset :"];
			XifNetNewSSHPresetView* view = ((XifNetAppDelegate*)[[NSApplication sharedApplication] delegate])->newSSHPresetView;
			[view->slaveLabel setStringValue:self->slaveFullName];
			[view->presetNameField setStringValue:@""];
			[view->usernameField setStringValue:@""];
			[view->sshfsPathField setStringValue:@""];
			[view->addArgsField setStringValue:@""];
			[view->sshKeyField setStringValue:@""];
			[alert setAccessoryView:view];
			NSInteger button = [alert runModal];
			if (button == NSAlertDefaultReturn) {
				[view->presetNameField validateEditing];
				[view->usernameField validateEditing];
				if (not ioslaves::validateName([[view->usernameField stringValue] UTF8String])) 
					return newPresetBlock();
				[view->sshfsPathField validateEditing];
				[view->addArgsField validateEditing];
				[view->sshKeyField validateEditing];
				if ([[view->sshKeyField stringValue] length] != 0) 
					[view->addArgsField setStringValue:[NSString stringWithFormat:@"%@ -o CheckHostIP=no -o \"IdentityFile=~/.ssh/%@\"", [view->addArgsField stringValue], [view->sshKeyField stringValue]]];
				NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
				NSMutableDictionary* prefsSlaves = [NSMutableDictionary dictionaryWithDictionary:[prefs dictionaryForKey:@"slaves"]];
				NSMutableDictionary* slavePrefs = [NSMutableDictionary dictionaryWithDictionary:[prefsSlaves objectForKey:[NSString stringWithStdString:self->slaveID]]];
				NSMutableArray* sshPresets = [NSMutableArray arrayWithArray:[slavePrefs objectForKey:@"ssh"]];
				NSDictionary* preset = [NSDictionary dictionaryWithObjectsAndKeys:[view->presetNameField stringValue], @"name",
				                                                                  [view->usernameField stringValue], @"user",
				                                                                  [view->sshfsPathField stringValue], @"path",
				                                                                  [view->addArgsField stringValue], @"args",
				                                                                  nil];
				[sshPresets addObject:preset];
				[slavePrefs setObject:sshPresets forKey:@"ssh"];
				[prefsSlaves setObject:slavePrefs forKey:[NSString stringWithStdString:self->slaveID]];
				[prefs setObject:prefsSlaves forKey:@"slaves"];
				[prefs synchronize];
				[self loadSshPresets];
				return;
			}
		}; newPresetBlock(); });
		return nil;
	}
	NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
	NSDictionary* prefsSlaves = [prefs dictionaryForKey:@"slaves"];
	NSDictionary* slavePrefs = [prefsSlaves objectForKey:[NSString stringWithStdString:self->slaveID]];
	NSArray* sshPresets = [slavePrefs objectForKey:@"ssh"];
	return [sshPresets objectAtIndex:[slaveSshPresets selectedSegment]-1];
}

- (IBAction)connectSSH:(id)sender {
	NSDictionary* preset = [self sshGetPreset];
	if (preset == nil) 
		return;
	NSString* script = [NSString stringWithFormat:@"ssh %@@%s.net.xif.fr %@", 
	                         [preset objectForKey:@"user"], self->slaveID.c_str(), [preset objectForKey:@"args"]];
	[NSThread detachNewThreadSelector:@selector(SSHSessionThread:) 
	                         toTarget:self
	                       withObject:script];
}
- (IBAction)connectSSHFS:(id)sender {
	NSDictionary* preset = [self sshGetPreset];
	if (preset == nil) 
		return;
	std::string volume_dir = _S("/Volumes/",[[preset objectForKey:@"name"] UTF8String]);
	int r = ::rmdir(volume_dir.c_str());
	if (r == -1) {
		if (errno == ENOENT);
		else if (errno == EBUSY) {
			[[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:[NSString stringWithStdString:volume_dir]]]; 
			return;
		} else {
			__log__(log_lvl::ERROR, "SSHFS", logstream << "rm " << volume_dir << " : " << strerror(errno));
			return;
		}
	}
	r = ::mkdir(volume_dir.c_str(), 0700);
	if (r == -1) {
		__log__(log_lvl::ERROR, "SSHFS", logstream << "mkdir " << volume_dir << " : " << strerror(errno));
		return;
	}
	NSBundle* bundle = [NSBundle mainBundle];
	NSString* script = [NSString stringWithFormat:@"sshfs -o nolocalcaches -o \"volicon=%@\" -o volname=\"%@\" -o idmap=file -o nomap=ignore -o uidfile=~/.ssh/sshfs-uids \"%@@%s.net.xif.fr:%@\" \"/Volumes/%@\" %@ && open \"/Volumes/%@\" && exit", 
	                                 [bundle pathForResource:@"sshfs_icon" ofType:@"icns"],
	                                                                           [preset objectForKey:@"name"],
	                                                                                                                                             [preset objectForKey:@"user"],
	                                                                                                                                                        self->slaveID.c_str(),
	                                                                                                                                                              [preset objectForKey:@"path"],
	                                                                                                                                                                              [preset objectForKey:@"name"],
	                                                                                                                                                                                   [preset objectForKey:@"args"],
	                                                                                                                                                                                                         [preset objectForKey:@"name"]];
	[NSThread detachNewThreadSelector:@selector(SSHSessionThread:) 
	                         toTarget:self
	                       withObject:script];
}
- (void)SSHSessionThread:(NSString*)shellScript {
	thread_controllers[::pthread_self()] = self;
	bool stop_ssh_after = true;
	std::string master_id, script;
	@autoreleasepool {
		script = [shellScript UTF8String];
		NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
		NSString* masterID = [prefs stringForKey:@"masterID"];
		if (masterID == nil) 
			return __log__(log_lvl::ERROR, NULL, "Master ID not set !");
		master_id = [masterID UTF8String];
	}
	::pthread_mutex_lock(&auth_mutex);
	RAII_AT_END_L( ::pthread_mutex_unlock(&auth_mutex) );
	arduino_auth_reuse_fd = 0;
	RAII_AT_END_N(arduino_reuse, {
		if (arduino_auth_reuse_fd > 0)
			::close(arduino_auth_reuse_fd);
		arduino_auth_reuse_fd = -1;
	});
	try {
		__log__(log_lvl::IMPORTANT, "SSH", logstream << "Starting sshd on slave '" << self->slaveID << "'...");
		socketxx::io::simple_socket<socketxx::base_netsock> sock = iosl_master::slave_connect(self->slaveID, 0, timeval{4,0});
		iosl_master::slave_command_auth(sock, master_id, ioslaves::op_code::SERVICE_START, _S(master_id,'.',self->slaveID));
		sock.o_str("ssh");
		ioslaves::answer_code o = (ioslaves::answer_code)sock.i_char();
		if (o != ioslaves::answer_code::OK) {
			__log__(log_lvl::ERROR, "SSH", logstream << "Failed to start ssh service : " << ioslaves::getAnswerCodeDescription(o));
			if (o != ioslaves::answer_code::BAD_STATE)
				return;
			else 
				stop_ssh_after = false;
		}
	} catch (std::exception& e) {
		return __log__(log_lvl::ERROR, "SSH", logstream << "Error while starting service : " << e.what());
	}
	@autoreleasepool {
		if ([[NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.Terminal"] count] == 0) {
			__log__(log_lvl::LOG, "SSH", "Launching Terminal.app...");
			[[NSWorkspace sharedWorkspace] launchApplication:@"Terminal"];
			::sleep(1);
		}
	}
	OSStatus err = ([] (const char* script) -> OSStatus {
		AppleEvent evt;
		OSStatus err;
		err = AEBuildAppleEvent(kAECoreSuite, kAEDoScript, 
		                        typeApplicationBundleID, "com.apple.terminal", 18L,
		                        kAutoGenerateReturnID, kAnyTransactionID, &evt, NULL,
		                        "'----':utf8(@)", strlen(script), script);
		if (err) return err;
		AppleEvent res;
		err = AESendMessage(&evt, &res, kAEWaitReply, kAEDefaultTimeout);
		AEDisposeDesc(&evt);
		if (err) return err;
		AEDesc desc;
		err = AEGetParamDesc(&res, keyErrorNumber, typeSInt32, &desc);
		AEDisposeDesc(&res);
		if (!err) {
			AEGetDescData(&desc, &err, sizeof(err));
			AEDisposeDesc(&desc);
		} else if (err == errAEDescNotFound)
			err = noErr;
		return err;
	})(script.c_str());
	if (err) 
		return __log__(log_lvl::ERROR, "SSH", logstream << "AppleEvent error while sending event to Terminal.app : " << err);
	@autoreleasepool {
		NSRunningApplication* terminalApp = [[NSRunningApplication runningApplicationsWithBundleIdentifier:@"com.apple.Terminal"] objectAtIndex:0];
		[terminalApp activateWithOptions:NSApplicationActivateIgnoringOtherApps];
		__log__(log_lvl::LOG, "SSH", logstream << "Executing '" << [shellScript UTF8String] << "'...");
		::dispatch_sync(dispatch_get_main_queue(), ^{
			[subMenu cancelTracking];
		});
	}
	if (not stop_ssh_after)
		return;
    ::sleep(4);
	try {
		__log__(log_lvl::IMPORTANT, "SSH", logstream << "Stopping sshd on slave '" << self->slaveID << "'...");
		socketxx::io::simple_socket<socketxx::base_netsock> sock = iosl_master::slave_connect(self->slaveID, 0, timeval{4,0});
		iosl_master::slave_command_auth(sock, master_id, ioslaves::op_code::SERVICE_STOP, _S(master_id,'.',self->slaveID));
		sock.o_str("ssh");
		ioslaves::answer_code o = (ioslaves::answer_code)sock.i_char();
		if (o != ioslaves::answer_code::OK) 
			__log__(log_lvl::ERROR, "SSH", logstream << "Failed to stop ssh service : " << ioslaves::getAnswerCodeDescription(o));
	} catch (std::exception& e) {
		return __log__(log_lvl::ERROR, "SSH", logstream << "Error while stopping service : " << e.what());
	}
}
- (IBAction)reconnect:(id)sender {
	if (isConnected or isConnecting) 
		return;
	[self slaveConnect];
}

- (IBAction)clearLog:(id)sender {
	[[logTextView textStorage] replaceCharactersInRange:NSMakeRange(0, [[logTextView textStorage] length]) withString:@""];
}

- (void)setMenuItem:(NSMenuItem*)menuItem {
	slaveMenuItem = [menuItem retain];
	subMenu = [[NSMenu alloc] init];
	controlSubMenuItem = [[NSMenuItem alloc] init];
	[controlSubMenuItem setView:slaveControlSubmenuView];
	[subMenu addItem:controlSubMenuItem];
	[subMenu setDelegate:self];
	subMenuItem = [[NSMenuItem alloc] init];
	[subMenuItem setView:slaveSubmenuView];
	[subMenu addItem:subMenuItem];
	[slaveMenuItem setSubmenu:subMenu];
	NSAssert(slaveMenuItem == [slaveMenuView enclosingMenuItem], @"menu item view enclosingMenuItem ≠ menu item");
}

- (void)dealloc {
	[slaveFullName release];
	[subMenuItem release];
	[controlSubMenuItem release];
	[subMenu release];
	[slaveMenuItem release];
	[super dealloc];
}

#define SLAVE_LABEL_ADDITIONAL_MENU_WIDTH  128/* IP label max size */ + 36/* status icon zone width */ + 50/* margin */
- (CGFloat)calculateMenuWidth {
	NSAttributedString* labelstr = [[NSAttributedString alloc] initWithString:slaveFullName 
	                                                               attributes:@{ NSFontAttributeName: slaveNameLabel.font } ];
	NSRect labelbounds = [labelstr boundingRectWithSize:NSMakeSize(FLT_MAX,FLT_MAX) 
	                                            options:NSStringDrawingUsesLineFragmentOrigin];
	return labelbounds.size.width + SLAVE_LABEL_ADDITIONAL_MENU_WIDTH;
}
- (void)setMenuWidth:(CGFloat)width {
	NSRect frameRect = [slaveMenuView frame];
	frameRect.size.width = width;
	[slaveMenuView setFrameSize:frameRect.size];
}

- (void)slaveConnect {
	NSAssert(not(isConnected or isConnecting), @"slaveConnect with connected or connecting state");
	[NSThread detachNewThreadSelector:@selector(slaveThread:) 
	                         toTarget:self
	                       withObject:nil];
	
}
- (bool)isConnected {
	return (bool)self->isConnected;
}

- (void)endConnWithMessage:(std::string)msg logLevel:(log_lvl)lvl statusIcon:(NSImage*)icon {
	isConnecting = false;
	[slaveConnectIndicator stopAnimation:nil];
	[slaveStatusImage setImage:icon];
	[slaveStatusImage setHidden:NO];
	timeval now;
	::gettimeofday(&now, NULL);
	[self addLogLineAtTime:now.tv_sec OfLevel:lvl isLocal:true inPart:"CONN" withMessage:msg];
	::slaves_init_conn_countdown--;
	if (::slaves_init_conn_countdown == 0) {
		if (arduino_auth_reuse_fd > 0)
			::close(arduino_auth_reuse_fd);
		arduino_auth_reuse_fd = -1;
	}
};

- (void)slaveThread:(id) object {
	thread_controllers[::pthread_self()] = self;
	std::function<void(NSImage*,std::string)> connectFail = [&] (NSImage* errorIcon, std::string logLine) {
		::dispatch_sync(dispatch_get_main_queue(), ^{
			[slaveReconnectButton setEnabled:YES];
			[self endConnWithMessage:logLine logLevel:(log_lvl::ERROR) statusIcon:errorIcon];
		});
	};
	try {
		fd_t stop_pipes[2];
		::pipe(stop_pipes);
		self->stopFD = stop_pipes[1];
		iosl_master::$silent = false;
		socketxx::base_netsock::addr_info addr ( _s(self->slaveID,'.',XIFNET_SLAVES_DOM), 
		                                         [&] () -> in_port_t { return iosl_master::slave_get_port_dns(self->slaveID); });
		::dispatch_sync(dispatch_get_main_queue(), ^{
			[self->slaveIPLabel setStringValue:[NSString stringWithStdString:addr.get_ip_str()]];
		});
		std::string master_id;
		@autoreleasepool {
			NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
			NSString* masterID = [prefs stringForKey:@"masterID"];
			if (masterID == nil) 
				return connectFail( icons::syserr, "Master ID not set" );
			master_id = [masterID UTF8String];
		}
		pthread_mutex_t* mutex = &auth_mutex;
		::pthread_mutex_lock(mutex);
		::dispatch_sync(dispatch_get_main_queue(), ^{
			isConnecting = true;
			[slaveReconnectButton setEnabled:NO];
			[slaveStatusImage setHidden:YES];
			[slaveConnectIndicator startAnimation:self];
		});
		RAII_AT_END({ 
			if (mutex != NULL) 
				::pthread_mutex_unlock(mutex);
		});
		auto sock = socketxx::simple_socket_client<socketxx::base_netsock> (addr, timeval{2,0});
		sock.set_read_timeout(timeval{1,0});
		iosl_master::slave_command_auth(sock, 
		                                master_id, 
		                                ioslaves::op_code::LOG_OBSERVE, 
		                                _S(master_id,'.',self->slaveID));
		::pthread_mutex_unlock(mutex);
		ioslaves::answer_code o = (ioslaves::answer_code)sock.i_char();
		if (o != ioslaves::answer_code::OK) 
			return connectFail( icons::error, logstream << "Async log dispatch subscribing refused : " << ioslaves::getAnswerCodeDescription(o) << logstr );
		mutex = NULL;
		::dispatch_sync(dispatch_get_main_queue(), ^{
			[self endConnWithMessage:logstream << "Connected to slave '" << self->slaveID << "'" << logstr logLevel:(log_lvl::DONE) statusIcon:(icons::up)];
			isConnected = true;
		});
		try {
			while (true) {
				socketxx::end::_socket_server::_select_throw_stop(sock.get_fd(), 
				                                                  stop_pipes[0], 
				                                                  NULL_TIMEVAL, true);
				time_t le_time = sock.i_int<uint64_t>();
				log_lvl le_lvl = (log_lvl)sock.i_char();
				std::string le_part = sock.i_str();
				std::string le_msg = sock.i_str();
				::dispatch_async(dispatch_get_main_queue(), ^{
					[self addLogLineAtTime:le_time OfLevel:le_lvl isLocal:false inPart:le_part withMessage:le_msg];
				});
			}
		} catch (socketxx::error& e) {
			::dispatch_sync(dispatch_get_main_queue(), ^{
				isConnected = false;
				[slaveStatusImage setImage:(icons::disconnected)];
				[slaveStatusImage setHidden:NO];
				[slaveReconnectButton setEnabled:YES];
				[self addLogLineAtTime:LOG_TIME_NOW OfLevel:(log_lvl::OOPS) isLocal:true inPart:"" withMessage:logstream << "Disconnected : " << e.what() << logstr];
			});
		} catch (socketxx::stop_event& e) {
			isConnected = false;
			return;
		}
	} catch (socketxx::end::client_connect_error& e) {
		return connectFail( icons::down, logstream << "Can't connect to slave '" << self->slaveID << "' : " << e.what() << logstr );
	} catch (socketxx::dns_resolve_error& e) {
		return connectFail( icons::unreachable, logstream << "Can't resolve hostname '" << e.failed_hostname << "'" << logstr );
	} catch (iosl_master::ldns_error& e) {
		return connectFail( icons::down, logstream << "Can't retrive ioslavesd port number : " << e.what() << logstr );
	} catch (socketxx::error& e) {
		return connectFail( icons::neterr, logstream << "Communication error with slave : " << e.what() << logstr );
	} catch (master_err& e) {
		if (e.is_ioslaves_err()) {
			switch (e.o) {
				case ioslaves::answer_code::NOT_AUTHORIZED: 
				case ioslaves::answer_code::DENY: 
					return connectFail( icons::forbidden, logstream << "Operation not authorized" << logstr );
				case ioslaves::answer_code::BAD_CHALLENGE_ANSWER: 
					return connectFail( icons::autherr, logstream << "Bad answer to slave " << self->slaveID << "'s challenge" << logstr );
				case ioslaves::answer_code::INTERNAL_ERROR: 
					return connectFail( icons::syserr, logstream << "System or internal error on slave '" << self->slaveID << "'" << logstr );
				default: 
					return connectFail( icons::error, e.what() );
			}
		}
		switch (e.ret) {
			case EXIT_FAILURE_AUTH: return connectFail( icons::autherr, e.what() );
			case EXIT_FAILURE_SYSERR: return connectFail( icons::syserr, e.what() );
			case EXIT_FAILURE_COMM: return connectFail( icons::neterr, e.what() );
			default: return connectFail( icons::error, e.what() );
				std::logic_error("");
		}
	}
}

- (void)addLogLineAtTime:(time_t)time OfLevel:(xlog::log_lvl)lvl isLocal:(bool)local inPart:(std::string)part withMessage:(std::string)msg {
	if (not local and [noVerboseLogCheckBox state] == NSOnState and msg.find("-- ") == 0) 
		return;
	if (time == LOG_TIME_NOW) {
		timeval now;
		::gettimeofday(&now, NULL);
		time = now.tv_sec;
	}
	msg = _S(part.empty()?_S(" "):_S(" [",part,"] "),msg,'\n');
	NSMutableAttributedString* textLine = [[NSMutableAttributedString alloc] initWithString:[NSString stringWithStdString:msg]];
	if (local) {
		[textLine setAttributes:@{
			NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11, NSFontItalicTrait),
			NSForegroundColorAttributeName : [NSColor colorWithCalibratedWhite:0.8f alpha:1.f]
		} range:NSMakeRange(0, [textLine length])];
		if (not part.empty())
			[textLine addAttribute:NSFontAttributeName 
			                 value:MakeLogAttrFont(@"Monaco", 10) 
			                 range:NSMakeRange(1, part.length()+2)];
		[textLine replaceCharactersInRange:NSMakeRange(0,0) withAttributedString:log_master_strs[(uint8_t)lvl]];
	} else {
		tm gmt_time;
		::gmtime_r(&time, &gmt_time);
		char time_str[30];
		::strftime(time_str, 30, "%d/%m %TZ ", &gmt_time);
		[textLine initWithString:[NSString stringWithUTF8String:time_str] attributes:@{
			NSFontAttributeName : MakeLogAttrFont(@"Menlo", 10),
			NSForegroundColorAttributeName : [NSColor colorWithCalibratedWhite:1.f alpha:1.f]
		}];
		[textLine replaceCharactersInRange:NSMakeRange([textLine length], 0) 
		              withAttributedString:log_lvl_strs[(uint8_t)lvl]];
		NSMutableAttributedString* msgAttrStr = [[NSMutableAttributedString alloc] initWithString:[NSString stringWithStdString:msg] attributes:@{
			NSFontAttributeName : MakeLogAttrFont(@"Menlo", 11),
			NSForegroundColorAttributeName : [NSColor colorWithCalibratedWhite:1.f alpha:1.f]
		}];
		if (not part.empty())
			[msgAttrStr addAttribute:NSFontAttributeName 
			                   value:MakeLogAttrFont(@"Monaco", 10) 
			                   range:NSMakeRange(1, part.length()+2)];
		[textLine replaceCharactersInRange:NSMakeRange([textLine length], 0) 
		              withAttributedString:msgAttrStr];
		[msgAttrStr release];
		XifNetAppDelegate* delegate = (XifNetAppDelegate*)[[NSApplication sharedApplication] delegate];
		switch (lvl) {
			case xlog::log_lvl::FATAL: case xlog::log_lvl::SEVERE:
				[delegate setState:AppState::StateSevere];
				[logDotRed setHidden:NO];
				break;
			case xlog::log_lvl::MAJOR:
				[delegate setState:AppState::StateMajor];
				[logDotBlue setHidden:NO];
				break;
			case xlog::log_lvl::ERROR:
				[delegate setState:AppState::StateError];
				[logDotRed setHidden:NO];
				break;
			case xlog::log_lvl::WARNING:
				if ([shutUpCheckBox state] != NSOnState)
					[delegate setState:AppState::StateWarning];
				[logDotYellow setHidden:NO];
				break;
			case xlog::log_lvl::IMPORTANT:
				if ([shutUpCheckBox state] != NSOnState)
					[delegate setState:AppState::StateImportant];
				[logDotBlue setHidden:NO];
				break;
			case xlog::log_lvl::LOG: case xlog::log_lvl::OOPS: case xlog::log_lvl::NOTICE: case xlog::log_lvl::DONE:
				if ([shutUpCheckBox state] != NSOnState)
					[delegate setState:AppState::StateLogLine];
				[logDotWhite setHidden:NO];
				break;
		}
	}
	NSTextStorage* text = [logTextView textStorage];
	[text replaceCharactersInRange:NSMakeRange([text length], 0) withAttributedString:textLine];
	[textLine release];
	if (NSMaxY([[logScrollView documentView] frame]) - NSMaxY([[logScrollView contentView] bounds]) < AUTO_SCROLL_TRIGGER) {
		NSPoint newScrollOrigin;
		if ([[logScrollView documentView] isFlipped]) {
			newScrollOrigin = NSMakePoint(0.f,NSMaxY([[logScrollView documentView] frame])-NSHeight([[logScrollView contentView] bounds]));
		} else {
			newScrollOrigin = NSMakePoint(0.f,0.f);
		}
		[[logScrollView documentView] scrollPoint:newScrollOrigin];
	}
}

- (void)menuWillOpen:(NSMenu*)menu {
	logSeenTimer = [NSTimer scheduledTimerWithTimeInterval:0.6 
	                                                target:self selector:@selector(logSeen) userInfo:nil 
	                                               repeats:NO];
	[[NSRunLoop mainRunLoop] addTimer:logSeenTimer forMode:NSRunLoopCommonModes];
}
- (void)menuDidClose:(NSMenu*)menu {
	if (logSeenTimer != nil) {
		[logSeenTimer invalidate];
		logSeenTimer = nil;
	} else {
		if (self->lastLogSeen+15 < ::time(NULL) and self->isConnected) {
			[self addLogLineAtTime:LOG_TIME_NOW OfLevel:(log_lvl::LOG) isLocal:true inPart:"" withMessage:"————————————————————————————————————————————————"];
			self->lastLogSeen = ::time(NULL);
		}
		[self logSeen];
	}
}
- (void)logSeen {
	logSeenTimer = nil;
	[logDotRed setHidden:YES];
	[logDotBlue setHidden:YES];
	[logDotYellow setHidden:YES];
	[logDotWhite setHidden:YES];
}

@end

@implementation XifNetSlaveItemView

- (void)drawRect:(NSRect)rect {
	if ([[self enclosingMenuItem] isHighlighted]) {
		NSColor* selectedColor = [NSColor colorWithCalibratedHue:0.602f saturation:0.74f brightness:0.84f alpha:1.f];
		NSGradient* gradient = [[NSGradient alloc] initWithColorsAndLocations:selectedColor, 0.0f,
		                                                                      selectedColor, 0.75f,
		                                                                      [NSColor controlBackgroundColor], 1.0f, nil];
		rect.size.width -= SLAVE_LABEL_ADDITIONAL_MENU_WIDTH - 45;
		[gradient drawInRect:rect angle:0];
		[slaveNameLabel setTextColor:[NSColor selectedMenuItemTextColor]];
	} else {
		[slaveNameLabel setTextColor:[NSColor textColor]];
	}
	[super drawRect:rect];
}
	
@end

@implementation XifNetSlaveLogView

- (void)drawRect:(NSRect)rect {
	[[NSColor colorWithCalibratedWhite:0.07f alpha:0.94f] set];
	NSRectFill(rect);
}

@end

