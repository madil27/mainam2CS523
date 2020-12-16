#ifndef VIRTUALFILE_H
#define VIRTUALFILE_H

/* Load the regexes in the given file. The file should be a list of regexes
 * separated by newlines, where each regex matches a virtual file.
 *
 * Return true if success, false otherwise.
 */
bool load_virtregexs(const char *path);

/* Return whether the given file path represents a virtual file.
 * (In particular, we are targeting files that cannot cause information flow.)
 *
 * Precondition: load_regex has succeeded.
 */
bool is_virtual(const char *path);

#endif
