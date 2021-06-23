# -*- coding:utf-8 -*-

import base64
import random
from OpenSSL import crypto
from const import CertConfig as const


class Ca(object):
    """
    根证信息
    """
    def __init__(self):
        self.ca_cert = self._get_root_cert()

    def _get_root_cert(self):
        with open(const.CA) as fd:
            return crypto.load_certificate(type=crypto.FILETYPE_PEM,
                                           buffer=fd.read())

    def subject(self):
        return self.ca_cert.get_subject()

    def private_key(self):
        with open(const.CERT_PRIVATE_KEY, "r") as fd:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, fd.read())


class Cert(object):
    """
    客户端证书信息
    """
    def __init__(self, cn_name, pwd, ca, rsa_len=const.CERT_RSA_LEN,
                 country=const.CERT_COUNTRY, province=const.CERT_PROVINCE,
                 city=const.CERT_CITY, company=const.CERT_COMPANY,
                 department=const.CERT_DEPARTMENT, email=const.CERT_EMAIL):
        self._ca = ca
        self._cn_name = cn_name
        self._pwd = pwd
        self._rsa_len = rsa_len
        self._cert_subjects = {
            "CN": cn_name,
            "C": country,
            "ST": province,
            "L": city,
            "O": company,
            "OU": department,
            "emailAddress": email
        }
        self._has_signed = False
        self._cert = crypto.X509()
        self._rsa_key = self._generate_rsa_key()

    def _generate_rsa_key(self):
        """
        生成 RSA 密钥对
        """
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, self._rsa_len)
        return k

    def _set_issuer(self):
        """
        设置颁发机构信息
        """
        self._cert.set_issuer(self._ca.subject())

    def _set_subject(self):
        """
        设置证书主题
        """
        cert_subj = self._cert.get_subject()
        for key, value in self._cert_subjects.items():
            setattr(cert_subj, key, value)
        self._cert.set_subject(self._cert.get_subject())

    def _set_version(self):
        """
        设置版本
        """
        self._cert.set_version(const.CERT_VERSION)

    def _set_public_key(self):
        """
        设置公钥
        """
        self._cert.set_pubkey(self._rsa_key)

    def _set_extend_infos(self):
        """
        设置扩展信息
        """
        self._cert.add_extensions([
            crypto.X509Extension(item["type_name"], item["critical"], item["value"])
            for item in const.CERT_EXTENDS
        ])
        self._cert.add_extensions([
            crypto.X509Extension(type_name="subjectKeyIdentifier",
                                 critical=False,
                                 value="hash",
                                 subject=self._cert),
            crypto.X509Extension(type_name="authorityKeyIdentifier",
                                 critical=False,
                                 value="keyid",
                                 issuer=self._ca.ca_cert)
        ])

    def _set_timeout(self):
        """
        设置过期时间
        """
        self._cert.gmtime_adj_notBefore(const.CERT_TIME_BEGIN)
        self._cert.gmtime_adj_notAfter(const.CERT_TIME_END)

    def _set_serial_number(self):
        """
        设置系列号
        """
        self._cert.set_serial_number(random.getrandbits(const.CERT_SERIAL_LEN))

    def _sign(self):
        """
        证书签名
        """
        if self._has_signed:
            return
        self._set_serial_number()
        self._set_version()
        self._set_timeout()
        self._set_issuer()
        self._set_subject()
        self._set_public_key()
        self._set_extend_infos()
        self._cert.sign(self._ca.private_key(), const.CERT_DIGEST)
        self._has_signed = True

    def get_cert_in_pem_fmt(self, with_b64_encode=False):
        """
        获取 PEM 格式私钥
        """
        self._sign()
        pem_cert = crypto.dump_certificate(type=crypto.FILETYPE_PEM,
                                           cert=self._cert).decode("utf-8")
        if with_b64_encode:
            return base64.b64encode(pem_cert)
        return pem_cert

    def get_cert_in_p12_fmt(self, with_b64_encode=False):
        """
        获取 P12 格式私钥
        """
        self._sign()
        _pfx = crypto.PKCS12()
        _pfx.set_privatekey(self._rsa_key)
        _pfx.set_certificate(self._cert)
        _pfx.set_ca_certificates([self._ca.ca_cert])
        pfx_data = _pfx.export(passphrase=self._pwd)
        if with_b64_encode:
            return base64.b64encode(pfx_data)
        return pfx_data

    def get_privatekey_in_pem_fmt(self, with_b64_encode=False):
        """
        获取 PEM 格式私钥
        """
        priv_key = crypto.dump_privatekey(type=crypto.FILETYPE_PEM,
                                          pkey=self._rsa_key).decode("utf-8")
        if with_b64_encode:
            return base64.b64encode(priv_key)
        return priv_key


if __name__ == "__main__":
    api = Cert(cn_name="cn_test_SDW-R_bb9b26c4",
               pwd="g0aEG4eGQCy9nJzHDPsL1rBlmx2MBowN",
               ca=Ca())

    cert_key_content = api.get_privatekey_in_pem_fmt()
    with open("./test.key", "w") as fd:
        fd.write(cert_key_content)

    cert_pem_content = api.get_cert_in_pem_fmt()
    with open("./test.crt", "w") as fd:
        fd.write(cert_pem_content)

    cert_p12_content = api.get_cert_in_p12_fmt(with_b64_encode=True)
    with open("./test.p12", "wb") as fd:
        fd.write(cert_p12_content)
