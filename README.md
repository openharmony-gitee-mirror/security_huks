# HUKS<a name="EN-US_TOPIC_0000001133264329"></a>

-   [Introduction](#section19960105154710)
-   [Directory Structure](#section11146193674920)
-   [Repositories Involved](#section1554141575016)

## Introduction<a name="section19960105154710"></a>

HUKS is a universal key management service. It provides KeyStore and Crypto APIs for applications to perform key management, encryption, and decryption operations.

HUKS consists of native APIs, the hardware abstraction layer \(HAL\), and Core Module.

1.  Native APIs are implemented using the C language to ensure consistency among all devices, and include the APIs for key generation, encryption, and decryption.
2.  HAL shields differences between hardware and OSs and defines the unified APIs for HUKS. It contains platform algorithm libraries, file systems, and logs.
3.  Core Module depends on the HAL and provides core functions such as encryption and decryption, signature verification, and key storage.

## Directory Structure<a name="section11146193674920"></a>

```
base/security
├── huks
│   ├── frameworks
│   │   └── huks_lite  HUKS code implementation
│   └── interfaces
│       └── innerkits
│           └── huks_lite  HUKS APIs
```

## Repositories Involved<a name="section1554141575016"></a>

[Security subsystem](https://gitee.com/openharmony/docs/blob/master/en/readme/security-subsystem.md)

**security\_huks**

[security\_deviceauth](https://gitee.com/openharmony/security_deviceauth/blob/master/README.md)

