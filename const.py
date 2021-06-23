# -*- coding:utf-8 -*-


class CertConfig:

    CER_TYPE_P12 = 0
    CER_TYPE_ROOT_CA = 1
    # 生成自签名 CA 的方法: https://blog.csdn.net/sing_sing/article/details/78556054
    CA = "/home/m_kepler/tmp/ca.crt"
    CERT_PRIVATE_KEY = "/home/m_kepler/tmp/ca.key"
    CERT_COUNTRY = "CN"
    CERT_PROVINCE = "GD"
    CERT_CITY = "SZ"
    CERT_COMPANY = "company"
    CERT_DEPARTMENT = "test"
    CERT_TIME_BEGIN = 0
    CERT_TIME_END = 3650 * 24 * 60 * 60
    CERT_VERSION = 2  # 版本为 3，0表示版本1
    CERT_RSA_LEN = 2048
    CERT_DIGEST = "sha1"
    CERT_EMAIL = "test@huagnjinjie.com"
    CERT_SERIAL_LEN = 64
    CERT_EXTENDS = [{
        "type_name": "basicConstraints",
        "critical": False,
        "value": "CA:FALSE"
    }, {
        "type_name": "nsComment",
        "critical": False,
        "value": "OpenSSL Generated Certificate"
    }]
