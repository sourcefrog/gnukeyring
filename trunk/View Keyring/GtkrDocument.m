//
//  GtkrDocument.m
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

#import "GtkrDocument.h"
#import "PrefsController.h"

@implementation GtkrDocument

- (id)init
{
    NSNotificationCenter *nc;
    
    if (self = [super init]) {
        nc = [NSNotificationCenter defaultCenter];
        [nc addObserver: self
               selector: @selector(dateFormatChanged:)
                   name: GtkrDateFormatChanged
                 object: nil];
        [nc addObserver: self
               selector: @selector(textFormatChanged:)
                   name: GtkrTextFormatChanged
                 object: nil];
    }
    return self;
}

- (void)dealloc
{
    NSNotificationCenter *nc;

    nc = [NSNotificationCenter defaultCenter];
    [nc removeObserver: self];
    [keyring release];
    [notesAttributes release];
    [super dealloc];
}

- (NSString *)windowNibName
{
    return @"GtkrDocument";
}

- (void)dateFormatChanged: (NSNotification *)note
{
    [self clickNameTable: self];
}

- (void)textFormatChanged: (NSNotification *)note
{
    [self clickNameTable: self];
}

- (void)updateUI
{
    [nameView reloadData];
    if ([keyring isUnlocked]) {
        [lockLabel setStringValue: NSLocalizedString(@"Lock", nil)];
        [lockButton setAction: @selector(lockDatabase:)];
        [lockButton setState: YES];
    } else {
        [lockLabel setStringValue: NSLocalizedString(@"Unlock", nil)];
        [lockButton setAction: @selector(unlockDatabase:)];
        [lockButton setState: NO];
    }
}    

- (void)windowControllerDidLoadNib:(NSWindowController *) aController
{
    NSArray *categories;
    int      i;
    
    [super windowControllerDidLoadNib:aController];
    notesAttributes = [[notes typingAttributes] retain];
    [category removeAllItems];
    categories = [keyring categories];
    // This array contains empty strings at the points for unused categories, so we
    // use that to set the item tags to the category position in the array.
    for (i = 0; i < [categories count]; i++) {
        if (![[categories objectAtIndex: i] isEqualToString: @""]) {
            [category addItemWithTitle: [categories objectAtIndex: i]];
            [[category lastItem] setTag: i];
        }
    }
    // Add an extra pseudo-category with an 'impossible' tag.
    [category addItemWithTitle: NSLocalizedString(@"All Category", nil)];
    [[category lastItem] setTag: [categories count]];
    [category selectItemWithTitle: NSLocalizedString(@"All Category", nil)];
    [keyring setCategory: [categories count]];
    [self updateUI];
}

- (NSData *)dataRepresentationOfType:(NSString *)aType
{
    return nil;
}

- (BOOL)loadDataRepresentation:(NSData *)data ofType:(NSString *)aType
{
    keyring = [[Keyring alloc] initWithData: data];
    if ([keyring isKeyring]) {
        return YES;
    }
    return NO;
}

- (IBAction)clickNameTable: (id)sender
{
    static NSCalendarDate *noDate = nil;
    unsigned realRecordIndex;
    int r = [nameView selectedRow];

    // The noDate value represents records with no real changed field
    // We don't think Palms were around in 1904.
    if (noDate == nil) {
        noDate = [NSCalendarDate dateWithYear: 1904
                                        month: 1
                                          day: 1
                                         hour: 0
                                       minute: 0
                                       second: 0
                                     timeZone: [NSTimeZone localTimeZone]];
        [noDate retain];
    }
        
    if (r != -1) {
        realRecordIndex = [[[keyring names] objectAtIndex: r] intValue];
        // always show the name, as it is not encrypted
        [name setStringValue: [keyring nameForIndex: realRecordIndex]];
    } else {
        // invalid row
        [name setStringValue: @""];
    }
    if ([keyring isUnlocked] && r != -1) {
        // unlocked keyring and valid row
        [account setStringValue:
            [keyring decryptedAccountNameForIndex: realRecordIndex]];
        [password setStringValue:
            [keyring decryptedPasswordForIndex: realRecordIndex]];
        if ([noDate isEqual: [keyring decryptedDateForIndex: realRecordIndex]] &&
            ![[NSUserDefaults
                standardUserDefaults] boolForKey: GtkrShowZeroDatesKey]) {
            [changed setStringValue: @""];
        } else {
            [changed setObjectValue:
                [keyring decryptedDateForIndex: realRecordIndex]];
        }
        // Set an empty string first, in order to clear down the typingAttributes
        // which might have changed due to silent font changes required to display
        // funny characters in the string.
        [notes setString: @""];
        [notes setString: [keyring decryptedNotesForIndex: realRecordIndex]];
    } else {
        // locked keyring, or invalid row
        [account setStringValue: @""];
        [password setStringValue: @""];
        [changed setStringValue: @""];
        [notes setString: @""];
    }
}

- (IBAction)changeCategory: (id)sender
{
    [keyring setCategory: [[category selectedItem] tag]];

    [nameView deselectAll: self];
    [self clickNameTable: self];
    [self updateUI];
}

- (IBAction)lockDatabase: (id)sender
{
    [keyring lock];
    [self clickNameTable: self];
    [self updateUI];
}

- (IBAction)unlockDatabase: (id)sender
{
    [enteredPassword setStringValue: @""];
    [NSApp beginSheet: passwordWindow
       modalForWindow: [name window]
        modalDelegate: self
       didEndSelector: @selector(sheetDidEnd:returnCode:contextInfo:)
          contextInfo: nil];
}

- (IBAction)endPasswordWindow: (id)sender
{
    [passwordWindow orderOut: sender];
    [NSApp endSheet: passwordWindow returnCode: [sender tag]];
}

- (IBAction)sheetDidEnd: (NSWindow *)sheet
             returnCode: (int)returnCode
            contextInfo: (void *)contextInfo
{
    if (returnCode == 0) {
        // OK
        if ([keyring unlock: [enteredPassword stringValue]]) {
            [self clickNameTable: self];
        } else {
            NSRunAlertPanel(NSLocalizedString(@"Wrong Password", nil),
                            NSLocalizedString(@"The password you entered is not the password used with this keyring.", nil),
                            NSLocalizedString(@"OK", nil), nil, nil);
        }
    }
    [self updateUI];
}

- (int)numberOfRowsInTableView: (NSTableView *)aTableView
{
    unsigned c = [[keyring names] count];
    return c;
}

- (id)tableView: (NSTableView *)aTableView
objectValueForTableColumn: (NSTableColumn *)aTableColumn
            row: (int)rowIndex
{
    return [keyring nameForIndex: [[[keyring names] objectAtIndex: rowIndex] intValue]];
}

@end
