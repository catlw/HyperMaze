#ifdef __cplusplus
extern "C"
{
#endif

#include <stdbool.h>
#include <stdint.h>
    char* hash(char* data,uint64_t size);
    char *genCMT(uint64_t value, char *sn_string, char *r_string);

    char *genConvertproof(uint64_t value,
                      uint64_t value_old,
                      char *sn_old_string,
                      char *r_old_string,
                      char *sn_string,
                      char *r_string,
                      char *cmtA_old_string, 
                      char *cmtA_string, 
                      uint64_t value_s);

    bool verifyConvertproof(char *data, char *cmtA_old_string, char *sn_old_string, char *cmtA_string, uint64_t value_s);


#ifdef __cplusplus
} // extern "C"
#endif