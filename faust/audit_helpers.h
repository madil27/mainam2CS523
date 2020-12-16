#include "open-flagtabs.h"

static const char *print_open_flags(const char *val)
{
  size_t i;
  unsigned int flags;
  int cnt = 0;
  char *out, buf[sizeof(open_flag_strings)+8];

  errno = 0;
  flags = strtoul(val, NULL, 16);
  if (errno) {
    if (asprintf(&out, "conversion error(%s)", val) < 0)
      out = NULL;
    return out;
  }

  buf[0] = 0;
  if ((flags & O_ACCMODE) == 0) {
    // Handle O_RDONLY specially                                                                                                                                                                                               
    strcat(buf, "O_RDONLY");
    cnt++;
  }
  for (i=0; i<OPEN_FLAG_NUM_ENTRIES; i++) {
    if (open_flag_table[i].value & flags) {
      if (!cnt) {
	strcat(buf,
	       open_flag_strings + open_flag_table[i].offset);
	cnt++;
      } else {
	strcat(buf, "|");
	strcat(buf,
	       open_flag_strings + open_flag_table[i].offset);
      }
    }
  }
  if (buf[0] == 0)
    snprintf(buf, sizeof(buf), "0x%s", val);
  return strdup(buf);
}
