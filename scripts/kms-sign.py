#!/usr/bin/env python3
"""Detached OpenPGP signatures from the KMS release key, for goreleaser.

  kms-sign.py <artifact> <signature>     sign, as goreleaser's signs cmd
  kms-sign.py --export-public-key <out>  armored public key for the Registry

KMS_SIGNING_KEY names the key, e.g. alias/terraform-provider-signing.
"""

import os
import sys
from pathlib import Path

from kms_pgp import KmsPgpSigner


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    signer = KmsPgpSigner(os.environ["KMS_SIGNING_KEY"])
    if sys.argv[1] == "--export-public-key":
        signer.export_public_key(sys.argv[2])
        return
    # Binary, not armored: Terraform reads SHA256SUMS.sig with
    # openpgp.CheckDetachedSignature, which does not dearmor
    Path(sys.argv[2]).write_bytes(signer.sign_bytes(Path(sys.argv[1]).read_bytes()))


if __name__ == "__main__":
    main()
