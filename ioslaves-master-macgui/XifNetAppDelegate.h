#import <Cocoa/Cocoa.h>
#include "macgui-common.h"

enum AppState {
	StateSevere,
	StateMajor,
	StateError,
	StateOops,
	StateWarning,
	StateImportant,
	StateLogLine,
	StateNormal
};

@interface XifNetNewSSHPresetView : NSView {
@public
	IBOutlet NSTextField* presetNameField;
	IBOutlet NSTextField* usernameField;
	IBOutlet NSTextField* sshfsPathField;
	IBOutlet NSTextField* addArgsField;
	IBOutlet NSTextField* sshKeyField;
	IBOutlet NSTextField* slaveLabel;
}
@end

@interface XifNetAppDelegate : NSObject <NSApplicationDelegate,NSMenuDelegate,XifLogger> {
@public
	NSStatusItem* statusItem;
	NSMenu* menu;
	NSMutableArray* slaveControllersArray;
	IBOutlet XifNetNewSSHPresetView* newSSHPresetView;
}

- (void)addLogLineAtTime:(time_t)time OfLevel:(xlog::log_lvl)lvl isLocal:(bool)local inPart:(std::string)part withMessage:(std::string)msg;

- (IBAction)setMasterID:(id)sender;
- (IBAction)reconnectAll:(id)sender;

- (void)setState:(AppState)state;
- (void)updateState:(NSTimer*)timer;

@end
