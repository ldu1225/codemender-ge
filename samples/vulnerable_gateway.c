/*
 * CodeMender 테스트용 C 취약점 샘플 파일 (CWE-120 / CWE-787 Buffer Overflow)
 */
#include <stdio.h>
#include <string.h>

void process_merchant_token(const char *untrusted_token, const char *merchant_id) {
    char token_buf[64];
    char audit_msg[128];

    /* [VULNERABLE: CWE-120 Classic Buffer Overflow via strcpy] */
    strcpy(token_buf, untrusted_token);

    /* [VULNERABLE: CWE-120 Unbounded Format String Copy via sprintf] */
    sprintf(audit_msg, "Merchant=%s Token=%s", merchant_id, token_buf);

    printf("%s\n", audit_msg);
}
