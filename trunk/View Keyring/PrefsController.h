//
//  PrefsController.h
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

/*!
* @const GtkrShowZeroDatesKey
 * @abstract NSUserDefaults key representing the "0 date" display behaviour.
 * @discussion The Keyring "record updated" field can sometimes be 0, which
 *             represents a date of 1 Jan 1904. This preference will
 *             suppress the display of those dates.
 */
extern NSString *GtkrShowZeroDatesKey;

/*!
 * @const GtkrTextIsJapaneseKey
 * @abstract NSUserDefaults key representing the Palm character set
 *           being used.
 * @discussion There's no way to determine algorithmically if the keyring
 *             database contains text encoded in Palm's Western encoding or
 *             Japanese encoding; this preference lets the user decide.
 */
extern NSString *GtkrTextIsJapaneseKey;

/*!
 * @const GtkrDateFormatChanged
 * @abstract Notification that "0 date" display behaviour has changed.
 * @discussion The Keyring "record updated" field can sometimes be 0, which
 *             represents a date of 1 Jan 1904. This notification is used
 *             to redisplay the record updated field.
 */
extern NSString *GtkrDateFormatChanged;

/*!
 * @const GtkrTextFormatChanged
 * @abstract Notification that the character set is changing between Western
 *           and Japanese.
 */
extern NSString *GtkrTextFormatChanged;

/*!
 * @class PrefsController
 * @abstract NSWindowController subclass that controls the preferences panel.
 */
@interface PrefsController : NSWindowController {
    IBOutlet NSButton *showZeroDates;
    IBOutlet NSButton *textIsJapanese;
}

/*!
 * @method changeZeroDates:
 * @abstract Action which notifies observers that the way to display certain
 *           dates has changed.
 * @param sender The object sending the action.
 */
- (IBAction)changeZeroDates: (id)sender;

/*!
 * @method changeTextFormat:
 * @abstract Action which notifies observers that the character set used
 *           in the keyring has changed.
 * @param sender The object sending the action.
 */
- (IBAction)changeTextFormat: (id)sender;

@end
