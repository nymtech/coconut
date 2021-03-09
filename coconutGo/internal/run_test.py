# Copyright 2021 Nym Technologies SA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
from typing import List


def base_args_go() -> List[str]:
    return ['go', 'run', '/home/jedrzej/workspace/coconut/coconutGo/internal/main.go']


def aggregate_keys_go():
    args = base_args_go() + ['aggregate-keys']
    pass


def aggregate_sigs_go():
    args = base_args_go() + ['aggregate-sigs']
    pass


def blind_sign_go(pubkey: str, pub_attributes: List[str], blind_sign_req: str, key: str, attributes: int) -> str:
    pub = ' '.join(pub_attributes)
    args = base_args_go() + ['blind-sign', '-a', str(attributes), '--elgamal', pubkey, '--pub', pub, '--req', blind_sign_req, '--key', key]
    return run_cmd(args)


def init_user_go() -> (str, str):
    args = base_args_go() + ['init-user']
    raw_out = run_cmd(args)
    split = raw_out.splitlines()
    return split[0], split[1]


def make_authorities_go(attributes: int, authorities: int, threshold: int) -> (List[str], List[str]):
    args = base_args_go() + ['init-issuers', '-n', str(authorities), '-t', str(threshold), '-a', str(attributes)]
    raw_out = run_cmd(args)
    keypairs = raw_out.split(b'\n\n')

    secret_keys = []
    verification_keys = []
    for key in keypairs:
        split = key.splitlines()
        if len(split) > 0:
            secret_keys.append(split[0])
            verification_keys.append(split[1])

    return secret_keys, verification_keys


def prepare_blind_sign_go(pubkey: str, pub_attributes: List[str], priv_attributes: List[str]) -> str:
    attributes = len(pub_attributes) + len(priv_attributes)
    pub = ' '.join(pub_attributes)
    priv = ' '.join(priv_attributes)
    args = base_args_go() + ['prepare-blind-sign', '--key', pubkey, '--pub', pub, '--priv', priv, '-a', str(attributes)]
    return run_cmd(args)


def prove_credential_go():
    args = base_args_go() + ['prove']
    pass


def randomize_go():
    args = base_args_go() + ['randomize']
    pass


def unblind_go(blinded_sig: str, key: str) -> str:
    args = base_args_go() + ['unblind', '--sig', blinded_sig, '--key', key]
    return run_cmd(args)


def verify_credential_go():
    args = base_args_go() + ['verify']
    pass


def run_cmd(args: List[str]) -> str:
    return subprocess.check_output(args)

def run_test():
    public_attributes = ['foomp', '100']
    private_attributes = ['aaa', 'bbb']
    attributes = len(public_attributes) + len(private_attributes)
    authorities = 3
    threshold = 2

    elgamal_priv, elgamal_pub = init_user_go()
    secret_keys, verification_keys = make_authorities_go(attributes, authorities, threshold)
    blind_sign_req = prepare_blind_sign_go(elgamal_pub, public_attributes, private_attributes)
    sigs = []
    for sk in secret_keys:
        blinded_sig = blind_sign_go(elgamal_pub, public_attributes, blind_sign_req, sk, attributes)
        sig = unblind_go(blinded_sig, elgamal_priv)
        sigs.append(sig)

    print(sigs)



def main():
    run_test()


if __name__ == "__main__":
    main()
