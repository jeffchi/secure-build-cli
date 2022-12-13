#!/usr/bin/env python3
#
# Licensed Materials - Property of IBM
#
# 5737-I09
#
# Copyright IBM Corp. 2019 All Rights Reserved.
# US Government Users Restricted Rights - Use, duplication or
# disclosure restricted by GSA ADP Schedule Contract with IBM Corp
#
import gnupg, json, logging, argparse, sys, os, re
from filters import JsonFilter

ha_public_key = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
8ty0LuCdUvbKsEuietRUgjEzuZ8FrA2q
=y8qG
-----END PGP PUBLIC KEY BLOCK-----
"""
ha_public_key_fingerprint = 'EC2412257ED36383F4371502ABC2BA1AA6572350'

hpvs_public_key = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=e08g
-----END PGP PUBLIC KEY BLOCK-----
"""

hpvs_public_key_fingerprint='B2D1E08676664055A1FBEC7CF1F85AF3DF626A30'

logger = logging.getLogger(__name__)

class ConfigCipher:
    def __init__(self, loglevel):
        logging.basicConfig(level=loglevel.upper())
        json_keys = {'ADMIN_PASSWORD', 'ROOT_SSH_KEY', 'CLIENT_CRT',
                     'DOCKER_BASE_PASSWORD', 'DOCKER_PASSWORD', 'DOCKER_RO_PASSWORD',
                     'GITHUB_KEY', 'MANIFEST_COS_API_KEY_ID', 'MANIFEST_COS_RESOURCE_CRN',
                     'BACKUP_COS_API_KEY_ID', 'BACKUP_COS_RESOURCE_CRN',
                     'COS_API_KEY_ID', 'COS_RESOURCE_CRN',
                     'CONTAINER_PUBLIC_KEY', 'CONTAINER_PRIVATE_KEY',
                     'APIKEY', 'RESOURCE_INSTANCE_ID', 'SESSION_KEY', 'TOKEN', 'SECRET', 'NEW_SECRET'
                     }
        filter = JsonFilter(json_keys)
        logger.addFilter(filter)
        self.gpg = gnupg.GPG()
        if not 'GPG_TTY' in os.environ or os.environ['GPG_TTY'] == '':
            os.environ['GPG_TTY'] = os.ttyname(0)
        logger.debug('ConfigCipher: GPG_TTY={}'.format(os.environ['GPG_TTY']))

    def list_keys(self):
        gpg = self.gpg
        logger.info('key list={}'.format(json.dumps(gpg.list_keys(), indent=4)))

    def delete_key(self, keyid, email='', passphrase=None):
        gpg = self.gpg
        logging.debug('keyid={} email={}'.format(keyid, email))
        found = False
        if not re.match(r'<.+@.+>', keyid) and email != '' and email != None:
            keyid = keyid + ' <' + email + '>'
        for key in gpg.list_keys(True):
            if 'uids' in key and keyid in key['uids']:
                logger.debug('delete_key: private key found={}'.format(json.dumps(key, indent=4)))
                logger.debug('delete_key: passphrase={}'.format(passphrase))
                if passphrase is None:
                    gpg.delete_keys(key['fingerprint'], True, expect_passphrase=False)
                else:
                    gpg.delete_keys(key['fingerprint'], True, passphrase=passphrase)
                found = True
        for key in gpg.list_keys():
            if 'uids' in key and keyid in key['uids']:
                logger.debug('delete_key: public key found={}'.format(json.dumps(key, indent=4)))
                gpg.delete_keys(key['fingerprint'])
                found = True
        if not found:
            logger.warning('delete_key: not found keyid={}'.format(keyid))

    def vendor_key(self, keyid, email):
        gpg = self.gpg
        logging.debug('vendor_key: keyid={} email={}'.format(keyid, email))
        keyid_email = keyid
        if not re.match(r'<.+@.+>', keyid) and email:
            keyid_email = keyid + ' <' + email + '>'
        found = 0
        for key in gpg.list_keys():
            if 'uids' in key and keyid_email in key['uids']:
                logger.debug('vendor_key: found={}'.format(json.dumps(key, indent=4)))
                vendor_key_fingerprint = key['fingerprint']
                found = found + 1
        if found > 1:
            logger.warning('vendor_key: {} keys found, using {}'.format(found, vendor_key_fingerprint))
        elif found == 0:
            logger.debug('vendor_key: generating a key keyid={}'.format(keyid))
            input_data = gpg.gen_key_input(key_type='RSA', key_length=4096, subkey_type='RSA', subkey_length=4096, expire_date=0, name_real=keyid, name_email=email)
            vendor_key = gpg.gen_key(input_data)
            vendor_key_fingerprint = str(vendor_key)
            logger.debug('vendor_key: generated key={}'.format(vendor_key_fingerprint))

        return vendor_key_fingerprint

    def import_ha_public_key(self):
        gpg = self.gpg
        for key in gpg.list_keys():
            if 'fingerprint' in key and key['fingerprint'] == ha_public_key_fingerprint:
                gpg.trust_keys(ha_public_key_fingerprint, 'TRUST_ULTIMATE')
                return ha_public_key_fingerprint
        import_result = gpg.import_keys(ha_public_key)
        if import_result.count != 1:
            logger.error('encrypt_config_json: failed importing a public key')
            return None
        fingerprint = import_result.fingerprints[0]
        logger.debug('encrypt_config_json: public key fingerprint={}'.format(fingerprint))
        gpg.trust_keys(fingerprint, 'TRUST_ULTIMATE')
        return fingerprint

    def import_hpvs_public_key(self):
        gpg = self.gpg
        for key in gpg.list_keys():
            if 'fingerprint' in key and key['fingerprint'] == hpvs_public_key_fingerprint:
                gpg.trust_keys(hpvs_public_key_fingerprint, 'TRUST_ULTIMATE')
                return hpvs_public_key_fingerprint
        import_result = gpg.import_keys(hpvs_public_key)
        if import_result.count != 1:
            logger.error('encrypt_config_json: failed importing HPVS public key')
            return None
        fingerprint = import_result.fingerprints[0]
        logger.debug('encrypt_config_json: public key fingerprint={}'.format(fingerprint))
        gpg.trust_keys(fingerprint, 'TRUST_ULTIMATE')
        return fingerprint

    def encrypt_config_json(self, config_json, email=None, keyid='secure_build'):
        gpg = self.gpg

        vendor_key_fingerprint = self.vendor_key(keyid, email)
        if vendor_key_fingerprint == '':
            logging.error('encrypt_config_json: failed obtaining a vendor key keyid={}'.format(keyid))
            return None
        logging.debug('encrypt_config_json: vendor_key_fingerprint={}'.format(vendor_key_fingerprint))
        config_json['vendor_key'] = gpg.export_keys(vendor_key_fingerprint)

        logger.debug('encrypt_config_json: config_json={}'.format(json.dumps(config_json, indent=4)))

        fingerprint = self.import_ha_public_key()
        if fingerprint is None:
            logging.error('encrypt_config_json: failed importing ha public key')
            return None

        logger.debug('encrypt_config_json: key list={}'.format(json.dumps(gpg.list_keys(), indent=4)))

        encrypted_ascii_data = gpg.encrypt(json.dumps(config_json), fingerprint, sign=vendor_key_fingerprint, armor=True)
        if not encrypted_ascii_data.ok:
            logger.error('encrypt_config_json: failed encrypting config json status={}'.format(encrypted_ascii_data.status))
            return None
        logger.debug('ok={} status={}'.format(encrypted_ascii_data.ok, encrypted_ascii_data.status))
        return str(encrypted_ascii_data)

    def encrypt_env_variables(self, base64data):
        gpg = self.gpg

        logger.debug('encrypt_env_variables: key list={}'.format(json.dumps(gpg.list_keys(), indent=4)))

        encrypted_ascii_data = gpg.encrypt(base64data, hpvs_public_key_fingerprint, armor=True)
        if not encrypted_ascii_data.ok:
            logger.error('encrypt_env_variables: failed encrypting config json status={}'.format(encrypted_ascii_data.status))
            return None
        logger.debug('ok={} status={}'.format(encrypted_ascii_data.ok, encrypted_ascii_data.status))
        return str(encrypted_ascii_data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='registration_file.py')
    parser.add_argument('command', help='[encrypt|list-keys|delete-key]')
    parser.add_argument('--loglevel', default='INFO', help='loglevel')
    parser.add_argument('--config-json-path', help='clear text config json file')
    parser.add_argument('--rd-path', help='encrypted registration file')
    parser.add_argument('--key-id', default='secure-build', help='vendor key id')
    parser.add_argument('--email', help='vendor key user email')
    #parser.add_argument('--passphrase', help='Vendor key id passphrase')
    args = parser.parse_args()

    for name in vars(args).keys():
        if vars(args)[name]:
            logger.debug(name + ' ' + str(vars(args)[name]))

    config_cipher = ConfigCipher(args.loglevel)

    if args.command == 'encrypt':
        try:
            with open(os.path.expanduser(args.config_json_path)) as f:
                config_json = json.load(f)
        except Exception as e:
            logger.error('failed reading config json file e={}'.format(e))
            sys.exit(-1)
        encrypted_config_json = config_cipher.encrypt_config_json(config_json, email=args.email, keyid=args.key_id)
        try:
            with open(os.path.expanduser(args.rd_path), 'w') as f:
                f.write(encrypted_config_json)
        except Exception as e:
            logger.error('failed writing registration file e={}'.format(e))
            sys.exit(-1)
    elif args.command == 'list-keys':
        config_cipher.list_keys()
    elif args.command == 'delete-key':
        config_cipher.delete_key(args.key_id, email=args.email)
    else:
        logger.error('unknown command: {}'.format(args.command))
