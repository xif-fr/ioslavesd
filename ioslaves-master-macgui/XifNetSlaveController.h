#import <Cocoa/Cocoa.h>
#include "macgui-common.h"
#include <string>
#include "log.h"

@interface XifNetSlaveItemView : NSView {
	IBOutlet NSTextField* slaveNameLabel;
}
@end
@interface XifNetSlaveLogView : NSView
@end

@interface XifNetSlaveController : NSViewController <XifLogger,NSMenuDelegate> {
	NSString* slaveFullName;
	std::string slaveID;
	
	IBOutlet XifNetSlaveItemView* slaveMenuView;
	IBOutlet NSTextField* slaveNameLabel;
	IBOutlet NSTextField* slaveIPLabel;
	IBOutlet NSImageView* slaveStatusImage;
	bool isConnecting, isConnected;
	IBOutlet NSProgressIndicator* slaveConnectIndicator;
	int stopFD;
	NSTimer* logSeenTimer;
	time_t lastLogSeen;
	IBOutlet NSImageView* logDotBlue;
	IBOutlet NSImageView* logDotRed;
	IBOutlet NSImageView* logDotYellow;
	IBOutlet NSImageView* logDotWhite;
	
	NSMenuItem* slaveMenuItem;
	NSMenu* subMenu;
	NSMenuItem* subMenuItem;
	IBOutlet NSView* slaveSubmenuView;
	IBOutlet NSTextView* logTextView;
	IBOutlet NSScrollView* logScrollView;
	NSMenuItem* controlSubMenuItem;
	IBOutlet NSView* slaveControlSubmenuView;
	IBOutlet NSButton* slaveReconnectButton;
	IBOutlet NSButton* slaveSSHButton;
	IBOutlet NSButton* slaveSSHFSButton;
	IBOutlet NSSegmentedControl* slaveSshPresets;
	IBOutlet NSButton* shutUpCheckBox;
	IBOutlet NSButton* noVerboseLogCheckBox;
	IBOutlet NSButton* clearLogButton;
}

- (id)initWithSlaveID:(std::string)slaveId fullName:(NSString*)fullName;
- (void)loadSshPresets;
- (void)slaveConnect;
- (bool)isConnected;

- (void)SSHSessionThread:(NSString*)shellScript;
- (NSDictionary*)sshGetPreset;
- (IBAction)connectSSH:(id)sender;
- (IBAction)connectSSHFS:(id)sender;
- (IBAction)reconnect:(id)sender;
- (IBAction)clearLog:(id)sender;

- (NSView*)slaveMenuView;
- (void)menuWillOpen;

- (CGFloat)calculateMenuWidth;
- (void)setMenuWidth:(CGFloat)width;

- (void)setMenuItem:(NSMenuItem*)menuItem;

- (void)slaveThread:(id)object;

#define LOG_TIME_NOW ((time_t)-1)
- (void)addLogLineAtTime:(time_t)time OfLevel:(xlog::log_lvl)lvl isLocal:(bool)local inPart:(std::string)part withMessage:(std::string)msg;

- (void)logSeen;

@end
