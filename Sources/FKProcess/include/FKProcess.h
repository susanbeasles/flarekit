#include <stddef.h>
int fk_run(const char *executable, const char *const *arguments, const char *const *environment,
           const char *cwd, const unsigned char *input, size_t input_size,
           const char *output_path, unsigned timeout_seconds);
