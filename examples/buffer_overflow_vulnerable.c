/**
 * Example: Buffer Overflow Vulnerability
 * This code demonstrates classic buffer overflow vulnerabilities in C
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * VULNERABLE: Uses strcpy without bounds checking
 * Can overflow the buffer if input is too large
 */
void unsafe_copy(char *user_input) {
    char buffer[100];
    strcpy(buffer, user_input);  // VULNERABLE: No bounds checking
    printf("Copied: %s\n", buffer);
}

/**
 * VULNERABLE: Uses gets() which is inherently unsafe
 * gets() has no way to limit input size
 */
void unsafe_input() {
    char buffer[64];
    printf("Enter your name: ");
    gets(buffer);  // VULNERABLE: Deprecated and unsafe
    printf("Hello, %s!\n", buffer);
}

/**
 * VULNERABLE: sprintf without size limit
 * Can overflow if formatted string is too long
 */
void unsafe_format(char *username, char *action) {
    char log_buffer[128];
    sprintf(log_buffer, "User %s performed action: %s", username, action);  // VULNERABLE
    printf("%s\n", log_buffer);
}

/**
 * VULNERABLE: strcat without checking remaining space
 * Multiple concatenations can overflow the buffer
 */
void unsafe_concatenation(char *str1, char *str2, char *str3) {
    char result[100];
    strcpy(result, str1);
    strcat(result, str2);  // VULNERABLE
    strcat(result, str3);  // VULNERABLE
    printf("Result: %s\n", result);
}

/**
 * VULNERABLE: Integer overflow leading to buffer overflow
 * If size is manipulated, can allocate small buffer but copy large data
 */
void unsafe_allocation(unsigned int size, char *data) {
    // VULNERABLE: size * 2 can overflow
    char *buffer = (char *)malloc(size * 2);
    if (buffer == NULL) {
        return;
    }

    // VULNERABLE: No validation that data fits in buffer
    strcpy(buffer, data);
    printf("Data: %s\n", buffer);
    free(buffer);
}

/**
 * VULNERABLE: Off-by-one error
 * Array indexing can go out of bounds
 */
void off_by_one_error(char *input) {
    char buffer[10];
    int i;

    // VULNERABLE: Should be i < 10, not i <= 10
    for (i = 0; i <= 10 && input[i] != '\0'; i++) {
        buffer[i] = input[i];
    }
    buffer[i] = '\0';  // VULNERABLE: Can write past end of buffer
}

int main() {
    printf("WARNING: This program contains intentional buffer overflow vulnerabilities!\n");
    printf("For educational purposes only. Do not compile or run on production systems.\n");

    /*
     * Example exploitation scenarios:
     *
     * 1. Stack-based buffer overflow:
     *    Input longer than 100 bytes to unsafe_copy() can overwrite return address
     *    and redirect execution flow
     *
     * 2. Heap overflow:
     *    Large input to unsafe_allocation() can corrupt heap metadata
     *
     * 3. Format string attack:
     *    Controlled format string in unsafe_format() can read/write arbitrary memory
     */

    return 0;
}
