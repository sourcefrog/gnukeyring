//
//  AboutController.m
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

#import "AboutController.h"


@implementation AboutController

- (id)init
{
    if (self = [super initWithWindowNibName: @"About"]) {
        [self setWindowFrameAutosaveName: @"AboutPanel"];
    }
    return self;
}

- (void)windowDidLoad
{
    NSDictionary *theDict = [[NSBundle mainBundle] localizedInfoDictionary];

    [copyright setStringValue: [theDict objectForKey: @"NSHumanReadableCopyright"]];
    [version setStringValue: [theDict objectForKey: @"CFBundleShortVersionString"]];
    [self hiliteAndActivateURLs: blurb];
    [icon setImage: [NSApp applicationIconImage]];
    [[self window] center];
}


// These next two methods are taken from:
// http://www.cocoadev.com/index.pl?ClickableUrlInTextView
- (void)hiliteAndActivateURLs:(NSTextView*)textView
{
    NSTextStorage* textStorage = [textView textStorage];
    NSString* string = [textStorage string];
    NSRange searchRange = NSMakeRange(0, [string length]);
    NSRange foundRange;

    [textStorage beginEditing];
    do {
        // We assume that all URLs start with http://
        foundRange = [string rangeOfString: @"http://"
                                   options: 0
                                     range: searchRange];

        if (foundRange.length > 0) { // Did we find a URL?
            NSURL* theURL;
            NSDictionary* linkAttributes;
            NSRange endOfURLRange;

            // Restrict the searchRange so that it won't find the same string again
            searchRange.location = foundRange.location + foundRange.length;
            searchRange.length = [string length] - searchRange.location;

            // We assume the URL ends with whitespace
            endOfURLRange = [string rangeOfCharacterFromSet:
                [NSCharacterSet whitespaceAndNewlineCharacterSet]
                                                    options: 0
                                                      range: searchRange];

            // The URL could also end at the end of the text.
            // The next line fixes it in case it does
            if (endOfURLRange.location == 0)
                endOfURLRange.location = [string length] - 1;

            // Set foundRange's length to the length of the URL
            foundRange.length = endOfURLRange.location - foundRange.location + 1;

            // grab the URL from the text
            theURL =[NSURL URLWithString:[string substringWithRange:foundRange]];

            // Make the link attributes
            linkAttributes = [NSDictionary dictionaryWithObjectsAndKeys: theURL, NSLinkAttributeName,
                [NSNumber numberWithInt:NSSingleUnderlineStyle], NSUnderlineStyleAttributeName,
                [NSColor blueColor], NSForegroundColorAttributeName,
                NULL];

            // Finally, apply those attributes to the URL in the text
            [textStorage addAttributes: linkAttributes
                                 range: foundRange];
        }

    } while (foundRange.length != 0); // repeat the do block until it no longer finds anything

    [textStorage endEditing];
}

- (BOOL)textView:(NSTextView*)textView
   clickedOnLink:(id)link
         atIndex:(unsigned)charIndex
{
    BOOL success;
    success=[[NSWorkspace sharedWorkspace] openURL: link];
    return success;
}

@end
