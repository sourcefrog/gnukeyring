#ifndef _PRONOUNCE_H_
#define _PRONOUNCE_H_

#define MAX_PWLEN             20

typedef struct {
  UInt16 unit_length;
  UInt16 saved_units;
  UInt8  units[MAX_PWLEN + 2];
} PronStateType;

#endif /* _PRONOUNCE_H_ */
