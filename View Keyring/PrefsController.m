//
//  PrefsController.m
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

#import "PrefsController.h"

NSString *GtkrShowZeroDatesKey = @"ShowZeroDates";
NSString *GtkrTextIsJapaneseKey = @"TextIsJapanese";
NSString *GtkrDateFormatChanged = @"GtkrDateFormatChanged";
NSString *GtkrTextFormatChanged = @"GtkrTextFormatChanged";

@implementation PrefsController

- (id)init
{
    if (self = [super initWithWindowNibName: @"Preferences"]) {
        [self setWindowFrameAutosaveName: @"PrefsPanel"];
    }
    return self;
}

- (void)windowDidLoad
{
    NSUserDefaults *defaults;

    defaults = [NSUserDefaults standardUserDefaults];
    [showZeroDates setState: [defaults boolForKey: GtkrShowZeroDatesKey]];
    [textIsJapanese setState: [defaults boolForKey: GtkrTextIsJapaneseKey]];
}

- (IBAction)changeZeroDates: (id)sender
{
    NSNotificationCenter *nc;

    [[NSUserDefaults standardUserDefaults] setBool: [sender state]
                                            forKey: GtkrShowZeroDatesKey];
    nc = [NSNotificationCenter defaultCenter];
    [nc postNotificationName: GtkrDateFormatChanged object: nil];
}

- (IBAction)changeTextFormat: (id)sender
{
    NSNotificationCenter *nc;

    [[NSUserDefaults standardUserDefaults] setBool: [sender state]
                                            forKey: GtkrTextIsJapaneseKey];
    nc = [NSNotificationCenter defaultCenter];
    [nc postNotificationName: GtkrTextFormatChanged object: nil];
}

@end
