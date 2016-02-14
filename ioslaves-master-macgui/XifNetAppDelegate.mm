#import "XifNetAppDelegate.h"
#import "XifNetSlaveController.h"
#import "macgui-common.h"

	// Misc
#include <stdexcept>
#include <xifutils/cxx.hpp>
#include <xifutils/objcxx.hh>
sig_atomic_t slaves_init_conn_countdown = SIG_ATOMIC_MIN;

	// Slave files
#include <sys/dir.h>
#include <libconfig.h++>

	// Common master
#include "log.h"
using namespace xlog;
#include "common.hpp"
#include "master.hpp"

	// Icons
NSImage* icons::unreachable = nil;
NSImage* icons::down = nil;
NSImage* icons::error = nil;
NSImage* icons::up = nil;
NSImage* icons::neterr = nil;
NSImage* icons::forbidden = nil;
NSImage* icons::syserr = nil;
NSImage* icons::autherr = nil;
NSImage* icons::disconnected = nil;

	// States
struct {
	AppState state;
	bool enabled;
	NSImage* icon;
	NSTimeInterval disp_time;
	NSTimer* timer;
} app_states[] = {
	#define AppStateLoadImage(rsrcPath) ([] () -> NSImage* { \
		@autoreleasepool { \
			NSBundle* bundle = [NSBundle mainBundle]; \
			return [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:rsrcPath ofType:@"png"]]; \
		} \
	})()
	{ AppState::StateSevere, false, AppStateLoadImage(@"xif_logo_err"), INFINITY, nil },
	{ AppState::StateMajor, false, AppStateLoadImage(@"xif_logo_maj"), 600.0, nil },
	{ AppState::StateError, false, AppStateLoadImage(@"xif_logo_err"), 360.0, nil },
	{ AppState::StateOops, false, AppStateLoadImage(@"xif_logo_err"), 0.80, nil },
	{ AppState::StateWarning, false, AppStateLoadImage(@"xif_logo_warn"), 120.0, nil },
	{ AppState::StateImportant, false, AppStateLoadImage(@"xif_logo_maj"), 300.0, nil },
	{ AppState::StateLogLine, false, AppStateLoadImage(@"xif_logo_log"), 0.40, nil },
	{ AppState::StateNormal, true, AppStateLoadImage(@"xif_logo"), INFINITY, nil }
};

@implementation XifNetNewSSHPresetView
@end

@implementation XifNetAppDelegate

- (void)awakeFromNib {
	thread_controllers[::pthread_self()] = self;
	NSBundle* bundle = [NSBundle mainBundle];
	icons::unreachable = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_cant" ofType:@"png"]];
	icons::down = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_down" ofType:@"png"]];
	icons::error = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_error" ofType:@"png"]];
	icons::up = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_up" ofType:@"png"]];
	icons::neterr = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_warn" ofType:@"png"]];
	icons::forbidden = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_forbid" ofType:@"png"]];
	icons::syserr = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_warnblue" ofType:@"png"]];
	icons::autherr = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_keywarn" ofType:@"png"]];
	icons::disconnected = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"stat_cross" ofType:@"png"]];
}

- (void)setState:(AppState)state {
	size_t i = 0;
	bool set_icon = true;
	do {
		if (::app_states[i].state == state) {
			::app_states[i].enabled = true;
			NSTimer*& timer = ::app_states[i].timer;
			if (timer != nil) {
				if ([timer isValid]) [timer invalidate];
				[timer release];
				timer = nil;
			}
			if (::app_states[i].disp_time != INFINITY) {
				timer = [[NSTimer alloc] initWithFireDate:[NSDate dateWithTimeIntervalSinceNow:app_states[i].disp_time] interval:0.f 
				                                   target:self selector:@selector(updateState:) userInfo:nil 
				                                  repeats:NO];
				[[NSRunLoop mainRunLoop] addTimer:timer forMode:NSRunLoopCommonModes];
			}
			if (set_icon) {
				NSImage* icon = ::app_states[i].icon;
				if (icon != nil) 
					[statusItem setImage:icon];
			}
			break;
		} else {
			if (::app_states[i].enabled) 
				set_icon = false;
		}
	} while (::app_states[i++].state != StateNormal);
}
- (void)updateState:(NSTimer*)timer {
	size_t i = 0;
	bool icon_set = false;
	do {
		if (timer != nil and ::app_states[i].timer == timer) {
			[::app_states[i].timer release];
			::app_states[i].timer = nil;
			::app_states[i].enabled = false;
		}
		if (not icon_set) {
			if (::app_states[i].enabled) {
				NSImage* icon = ::app_states[i].icon;
				if (icon != nil) 
					[statusItem setImage:icon];
				icon_set = true;
			}
		}
	} while (::app_states[i++].state != StateNormal);
}

- (void)menuWillOpen:(NSMenu*)menu {
	[self menuDidClose:nil];
	for (size_t i = 0; i < [slaveControllersArray count]; i++) 
		[[slaveControllersArray objectAtIndex:i] menuWillOpen];
}
- (void)menuDidClose:(NSMenu*)menu {
	for (size_t i = 0; ::app_states[i].state != StateNormal; i++) {
		::app_states[i].enabled = false;
		NSTimer*& timer = ::app_states[i].timer;
		if (timer != nil) {
			if ([timer isValid]) [timer invalidate];
			[timer release];
			timer = nil;
		}
	}
	[self updateState:nil];
}

- (void)addLogLineAtTime:(time_t)time OfLevel:(xlog::log_lvl)lvl isLocal:(bool)local inPart:(std::string)part withMessage:(std::string)msg {
	NSLog(@"Unexcepted log line in main thread : [%s] %s", part.c_str(), msg.c_str());
}

- (void)applicationDidFinishLaunching:(NSNotification*)notif {
	statusItem = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength] retain];
	NSBundle* bundle = [NSBundle mainBundle];
    NSImage* statusRegImage = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"xif_logo" ofType:@"png"]];
	[statusItem setImage:statusRegImage];
	[statusRegImage release];
	NSImage* statusAltImage = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"xif_logo_sel" ofType:@"png"]];
    [statusItem setAlternateImage:statusAltImage];
	[statusAltImage release];
	[statusItem setHighlightMode:YES];
	menu = [[NSMenu alloc] init];
	[menu setDelegate:self];
	CGFloat maxMenuWidth = 0.f;
	
	slaveControllersArray = [[NSMutableArray alloc] init];
	size_t ni;
	DIR* slaves_dir = ::opendir(IOSLAVES_MASTER_SLAVES_DIR);
	if (slaves_dir == NULL) 
		throw xif::sys_error("can't open slaves dir");
	RAII_AT_END_L( ::closedir(slaves_dir) );
	dirent* dp = NULL;
	while ((dp = ::readdir(slaves_dir)) != NULL) {
		for (ni = 1; ni <= 5; ni++)
			if (dp->d_name[::strlen(dp->d_name)-ni] != ".conf"[5-ni]) 
				goto __dp_loop_next;
		try {
			std::string slave_name = std::string(dp->d_name).substr(0, ::strlen(dp->d_name)-ni+1);
			if (slave_name.length() < 3 or !ioslaves::validateSlaveName(slave_name)) 
				continue;
			std::string fname = _S( IOSLAVES_MASTER_SLAVES_DIR,"/",std::string(dp->d_name) );
			FILE* slave_f = ::fopen(fname.c_str(), "r");
			if (slave_f == NULL)
				throw xif::sys_error(logstream << "failed to open slave info file for " << slave_name << logstr);
			RAII_AT_END_L( ::fclose(slave_f) );
			NSString* fullName = nil;
			try {
				libconfig::Config conf;
				conf.read(slave_f);
				const char* fullname = conf.lookup("fullname");
				fullName = [[NSString alloc] initWithUTF8String:fullname];
			} catch (const libconfig::ParseException& e) {
				throw std::runtime_error(logstream << "Parse error in slave file of " << slave_name << " at line " << e.getLine() << " : " << e.getError() << logstr);
			} catch (const libconfig::SettingException& e) {
				throw std::runtime_error(logstream << "Missing/bad field @" << e.getPath() << " in slave file of " << slave_name << logstr);
			}
			XifNetSlaveController* slaveController = [[XifNetSlaveController alloc] initWithSlaveID:slave_name 
																						   fullName:fullName];
			[fullName release];
			[slaveControllersArray addObject:slaveController];
			[slaveController release];
			CGFloat slaveLabelWidth = [slaveController calculateMenuWidth];
			maxMenuWidth = std::max(maxMenuWidth, slaveLabelWidth);
		} catch (const std::runtime_error& e) {
			NSAlert *alert = [[NSAlert alloc] init];
			[alert addButtonWithTitle:@"OK"];
			[alert setMessageText:@"Can't load slave !"];
			[alert setInformativeText:[NSString stringWithUTF8String:e.what()]];
			[alert setAlertStyle:NSCriticalAlertStyle];
			[alert runModal];
			[alert release];
		}
	__dp_loop_next:
		continue;
	}
	
	::slaves_init_conn_countdown = (int)[slaveControllersArray count];
	for (size_t i = 0; i < [slaveControllersArray count]; i++) {
		XifNetSlaveController* slaveController = [slaveControllersArray objectAtIndex:i];
		[slaveController setMenuWidth:maxMenuWidth];
		NSMenuItem* menuItem = [[NSMenuItem alloc] init];
		[menuItem setView:[slaveController slaveMenuView]];
		[menu addItem:menuItem];
		[slaveController setMenuItem:menuItem];
		[menuItem release];
		[slaveController slaveConnect];
	}
	
	[menu addItem:[NSMenuItem separatorItem]];
	NSMenuItem* setMasterIDMenuItem = [[NSMenuItem alloc] initWithTitle:@"Set master ID…" 
																 action:@selector(setMasterID:) 
														  keyEquivalent:@""];
	[menu addItem:setMasterIDMenuItem];
	[setMasterIDMenuItem release];
	NSMenuItem* reconnectAllMenuItem = [[NSMenuItem alloc] initWithTitle:@"Reconnect all" 
																 action:@selector(reconnectAll:) 
														  keyEquivalent:@""];
	[menu addItem:reconnectAllMenuItem];
	[reconnectAllMenuItem release];
	NSMenuItem* quitMenuItem = [[NSMenuItem alloc] initWithTitle:@"Quit" 
	                                                      action:@selector(terminate:) 
	                                               keyEquivalent:@""];
	[menu addItem:quitMenuItem];
	[quitMenuItem release];
	
	[statusItem setMenu:menu];
	[menu release];
}

- (IBAction)setMasterID:(id)sender {
	NSAlert* alert = [NSAlert alertWithMessageText:@"Master ID"
                                     defaultButton:@"OK"
                                   alternateButton:@"Cancel"
                                       otherButton:nil
                         informativeTextWithFormat:@"Please enter a new valid master ID :"];
    NSTextField* input = [[NSTextField alloc] init];
	[input sizeToFit];
	[input setFrameSize:NSMakeSize(300, [input frame].size.height)];
    [alert setAccessoryView:input];
	[input becomeFirstResponder];
	[input release];
    NSInteger button = [alert runModal];
    if (button == NSAlertDefaultReturn) {
        [input validateEditing];
        NSString* masterID = [input stringValue];
		if (not ioslaves::validateMasterID([masterID UTF8String])) 
			return [self setMasterID:self];
		NSUserDefaults* prefs = [NSUserDefaults standardUserDefaults];
		[prefs setObject:masterID forKey:@"masterID"];
		[prefs synchronize];
    }
}

- (IBAction)reconnectAll:(id)sender {
	for (size_t i = 0; i < [slaveControllersArray count]; i++) {
		XifNetSlaveController* slaveController = [slaveControllersArray objectAtIndex:i];
		if (not [slaveController isConnected]) {
			::slaves_init_conn_countdown++;
			[slaveController slaveConnect];
		}
	}
}

- (void)dealloc {
	[super dealloc];
	[[NSStatusBar systemStatusBar] removeStatusItem:statusItem];
	[statusItem release];
	[menu release];
	[slaveControllersArray release];
};

@end
