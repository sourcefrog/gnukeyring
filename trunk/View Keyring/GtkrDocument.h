//
//  GtkrDocument.h
//  View Keyring
//
// Copyright (c) 2003, Chris Ridd <chrisridd@mac.com>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// * Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the name of the Keyring for PalmOS project nor the names of
//   its contributors may be used to endorse or promote products derived
//   from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// $Id$

#import <Cocoa/Cocoa.h>
#import "Keyring.h"

/*!
 * @class GtkrDocument
 * @abstract An NSDocument subclass representing an instance of a Keyring
 *           for PalmOS backup file.
 */
@interface GtkrDocument : NSDocument
{
    Keyring *keyring;

    IBOutlet NSTableView *nameView;
    IBOutlet NSTextField *name;
    IBOutlet NSTextField *account;
    IBOutlet NSTextField *password;
    IBOutlet NSTextField *changed;
    IBOutlet NSTextView  *notes;
    NSDictionary *notesAttributes;
    IBOutlet NSButton    *lockButton;
    IBOutlet NSTextField *lockLabel;
    IBOutlet NSPopUpButton *category;
    IBOutlet NSWindow    *passwordWindow;
    IBOutlet NSSecureTextField *enteredPassword;
}

/*!
 * @method lockDatabase:
 * @abstract Action method which locks an unlocked database.
 * @param sender The object sending the action.
 */
- (IBAction)lockDatabase: (id)sender;

/*!
 * @method unlockDatabase:
 * @abstract Action method which unlocks a locked database.
 * @discussion Prompts for a password.
 * @param sender The object sending the action.
 */
- (IBAction)unlockDatabase: (id)sender;

/*!
 * @method changeCategory:
 * @abstract Action method which changes the category according to the
 *           category popup menu.
 * @param sender The object sending the action.
 */
- (IBAction)changeCategory: (id)sender;

/*!
 * @method clickNameTable:
 * @abstract Action method which simulates a click in the name table.
 * @discussion Mainly used to refresh the display.
 * @param sender The object sending the action.
 */
- (IBAction)clickNameTable: (id)sender;

/*!
 * @method endPasswordWindow:
 * @abstract Action method which ends the password entering sheet.
 * @param sender The object sending the action.
 */
- (IBAction)endPasswordWindow: (id)sender;

/*!
 * @method updateUI
 * @abstract Action method which updates all the changeable bits of the UI.
 */
- (void)updateUI;

// Data source methods

/*!
 * @method numberOfRowsInTableView:
 * @abstract Data source delegate method.
 * @discussion Returns the number of keys in the current category.
 * @param aTableView The table containing the key names.
 * @result The number of keys in the current category.
 */

- (int)numberOfRowsInTableView: (NSTableView *)aTableView;

/*!
 * @method tableView:objectValueForTableColumn:row:
 * @abstract Data source delegate method.
 * @param aTableView The table view (ignored).
 * @param aTableColumn The table view's column (ignored).
 * @param rowIndex The displayed row in the table to return.
 * @discussion Returns the key name for the given row. The true key index
 *              is calculated from rowIndex, and depends on the selected
 *              category.
 */
- (id)tableView: (NSTableView *)aTableView
objectValueForTableColumn: (NSTableColumn *)aTableColumn
            row: (int)rowIndex;

@end
