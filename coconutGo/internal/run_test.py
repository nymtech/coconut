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
from typing import Optional
import random


def base_args_go() -> List[str]:
    return ['./coconut-cli-go']


def aggregate_keys_go(keys: List[str], indices: List[int]) -> str:
    ids = ' '.join([str(idx) for idx in indices])
    key_arg = ' '.join(keys)

    args = base_args_go() + ['aggregate-keys', '--keys', key_arg, '--indices', ids]
    return run_cmd(args)


def aggregate_sigs_go(sigs: List[str], indices: List[int]) -> str:
    ids = ' '.join([str(idx) for idx in indices])
    sig_arg = ' '.join(sigs)
    args = base_args_go() + ['aggregate-sigs', '--sigs', sig_arg, '--indices', ids]
    return run_cmd(args)


def blind_sign_go(pubkey: str, pub_attributes: List[str], blind_sign_req: str, key: str, attributes: int) -> str:
    pub = ' '.join(pub_attributes)
    args = base_args_go() + ['blind-sign', '-a', str(attributes), '--elgamal', pubkey, '--pub', pub, '--req',
                             blind_sign_req, '--key', key]
    return run_cmd(args)


def init_user_go() -> (str, str):
    args = base_args_go() + ['init-user']
    raw_out = run_cmd(args)
    split = raw_out.splitlines()
    return split[0], split[1]


def make_authorities_go(attributes: int, authorities: int, threshold: int) -> (List[str], List[str]):
    args = base_args_go() + ['init-issuers', '-n', str(authorities), '-t', str(threshold), '-a', str(attributes)]
    raw_out = run_cmd(args)
    keypairs = raw_out.split('\n\n')

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


def prove_credential_go(sig: str, aggr_vk: str, priv_attributes: List[str], attributes: int) -> str:
    priv = ' '.join(priv_attributes)

    args = base_args_go() + ['prove', '--sig', sig, '--key', aggr_vk, '--priv', priv, '-a', str(attributes)]
    return run_cmd(args)


def randomize_go(sig: str) -> str:
    args = base_args_go() + ['randomize', '--sig', sig]
    return run_cmd(args)


def unblind_go(blinded_sig: str, key: str) -> str:
    args = base_args_go() + ['unblind', '--sig', blinded_sig, '--key', key]
    return run_cmd(args)


# "verify [--key aggregated-verification-key] [--theta credential-proof] [-a number-of-attributes]",
def verify_credential_go(pub_attributes: List[str], theta: str, aggr_vk: str, attributes: int) -> bool:
    pub = ' '.join(pub_attributes)

    args = base_args_go() + ['verify', '--theta', theta, '--key', aggr_vk, '--pub', pub, '-a', str(attributes)]
    out = run_cmd(args)

    if 'ok' in out:
        return True
    else:
        return False


def run_cmd(args: List[str], cwd: Optional[str] = None) -> str:
    out = subprocess.check_output(args, cwd=cwd)
    return out.decode('utf-8')


def choose_n_random_with_indices(n: int, items: List[str]) -> (List[str], List[int]):
    indices = [i for i in range(1, len(items) + 1)]
    sample = random.sample(indices, k=n)

    new_items = []
    for idx in sample:
        new_items.append(items[idx - 1])

    return new_items, sample


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

    # all_indices = [i for i in range(1, len(sigs) + 1)]

    (chosen_sigs, chosen_indices) = choose_n_random_with_indices(threshold, sigs)

    aggr_sig = aggregate_sigs_go(chosen_sigs, chosen_indices)
    sig_prime = randomize_go(aggr_sig)

    (chosen_keys, chosen_indices) = choose_n_random_with_indices(threshold, verification_keys)
    aggr_key = aggregate_keys_go(chosen_keys, chosen_indices)
    theta = prove_credential_go(sig_prime, aggr_key, private_attributes, attributes)

    did_verify = verify_credential_go(public_attributes, theta, aggr_key, attributes)

    return did_verify


def build_binaries():
    args = ['go', 'build', '-o', 'coconut-cli-go', 'main.go']
    cwd = '/home/jedrzej/workspace/coconut/coconutGo/internal'
    run_cmd(args, cwd)


def main():
    build_binaries()
    ok = 0
    fail = 0

    for i in range(100):
        print("test", i+1, '.....', end='')
        if run_test():
            print(' OK')
            ok += 1
        else:
            print('FAILURE')
            fail += 1

    print("ok: ", ok, "fail: ", fail)


if __name__ == "__main__":
    main()
