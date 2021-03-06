/* -*- mode: c; c-indentation-style: "java"; c-basic-offset: 4 -*-
 *
 * $Id$
 * 
 * Keyring -- store passwords securely on a handheld
 * Copyright (C) 1999, 2000 by Martin Pool <mbp@users.sourceforge.net>
 * Copyright (C) 2002-2005 Jochen Hoenicke <hoenicke@users.sourceforge.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define fntStar				 128
#define fntPassword			 129

#define ListForm			1000
#define KeyEditForm			1001
#define AboutForm			1002
#define UnlockForm			1003
#define WrongKeyAlert			1004
#define ChecksumForm			1006
#define SecurityForm			1007
#define NotImplementedAlert		1008
#define ConfirmDeleteForm		1009
#define SetPasswdForm			1010
#define ConfirmPasswdForm		1011
#define PasswdMismatchAlert		1012
#define InitForm			1014
#define BusyEncryptForm			1015
#define BusyDecryptForm			1016
#define GenerateForm			1017
#define MemoDatabaseErrorAlert		1018
#define OutOfMemoryAlert		1019
#define CouldntLaunchMemoAlert		1020
#define CryptoErrorAlert		1021
#define UpgradeAlert			1023
#define TooNewAlert			1024
#define CantUpgradeAlert		1025
#define UpgradeFailedAlert		1026
#define NotEnoughFeaturesAlert          1027
#define BetaAlert                       1028
#define CipherNotSupportedAlert         1029
#define UpgradeReadOnlyAlert            1030
#define PasswordHashMissingAlert        1031
#define ExportEmptyAlert                1032
#define OfferReadOnlyAlert              1033
#define ReadOnlyAlert                   1034
#define ReencryptAlert                  1035
#define CreateDBAlert                   1036
#define SnibDatabaseAlert               1037
#define KeyDatabaseAlert                1038
#define PrefsForm                       1039
#define SortErrorAlert                  1040


#define ListMenuBar			1100
#define KeyEditMenuBar			1101
#define GnuBitmap			1102
#define KeyringBitmap			1103
#define NoteBitmap			1104
#define FieldsBitmap			1105
#define KeyBitmap                       1106
#define LockBitmap                      1107
#define UnlockBitmap                    1108

#define StarFont			1150
#define PasswordFont			1151

#define DoneBtn				1202
#define CountDownTrigger		1204
#define LockBtn				1205
#define UnlockBtn			1206
#define CancelBtn			1207
#define SecurityBtn			1208
#define MasterKeyFld			1209
#define DateTrigger			1210
#define NewKeyBtn			1211
#define AccountField			1212
#define PasswordField			1213
#define MessageField			1214
#define MD5Push				1215
#define MD4Push				1216
#define SumField			1217
#define SumBtn				1218
#define OkBtn				1219
#define SaveArchiveCheck		1220
#define NotesScrollbar			1222
#define TitleTemplateStr		1223
#define EmptyTitleStr			1224
#define Expiry0Push			1225
#define Expiry15Push			1226
#define Expiry60Push			1227
#define Expiry300Push			1228
#define ConfirmFld			1229
#define LengthFld			1230
#define Length4Push			1231
#define Length6Push			1232
#define Length8Push			1233
#define Length10Push			1234
#define Length16Push			1235
#define Length20Push			1236
#define IncludeLower			1237
#define IncludeUpper			1238
#define IncludeDigits			1239
#define IncludePunct			1240
#define GenerateBtn			1241
#define CategoryTrigger			1242
#define CategoryList			1243
#define VeilPasswordCheck		1244
#define LookUpFld			1245
#define KeyringFontsCheck		1246
#define Iter2500Push                    1247
#define Iter5000Push                    1248
#define Iter250Push                     1249
#define Iter500Push                     1250
#define Iter1000Push                    1251
#define LabelList			1252
//#define CipherNoPush                    1253
#define CipherDESPush                   1254
#define CipherAES128Push                1255
#define CipherAES256Push                1256
#define KeyringKeepCheck		1257
#define IncludeHigh                     1258
#define IncludeSyllables                1259
#define IncludeHex                      1260
#define NotesField                      1261
#define KeyNameField                    1262
#define KeyTableScrollBar               1263
#define KeyTable                        1264

#define AboutCmd			1300
#define ChecksumCmd			1303
#define SecurityCmd			1304
#define DeleteKeyCmd			1305
#define SetPasswdCmd			1306
#define GenerateCmd			1308
#define ExportMemoCmd			1309
#define HelpCmd				1310
#define UndoAllCmd                      1311
#define PrefsCmd                        1312

#define ChangeDateStr                   1400
#define KeyringFindStr                  1401

#define GenerateHelp			1502
#define KeyEditHelp			1504
#define SetPasswdHelp                   1505

#define ErrCheckingROM                  1600

#define CategoryRsrc			2000

