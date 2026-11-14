package com.erp.auth.domain.port;

import com.erp.auth.domain.valueobject.OtpCodeHash;

public interface OtpCodeHasher {
    OtpCodeHash hash(String rawCode);
}
