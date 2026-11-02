"""Fetch the original Bitcoin source files this model was ported from, and verify them.

Each file is taken from the official repository at the stated commit and checked against
the SHA-256 recorded when the model was written. A mismatch is reported and the file is
not kept.

    python fetch_sources.py            # writes sources/<commit>/<file>
"""

import hashlib
import os
import sys
import urllib.request

REPO = "https://raw.githubusercontent.com/bitcoin/bitcoin"

SOURCES = [
    # 0.1.5 — SVN trunk@1, 30 August 2009 (serialize.h: VERSION = 105)
    ("e071a3f6c06f", "script.h", "f905858b5d6d4593a3051b593c45fb5a8dd4cd38b5636c5e4456060b034fa218"),
    ("e071a3f6c06f", "script.cpp", "347c7526932d42a4d10ae487150b709e2ead737aa4b05f50aa9e2eefeb05a5b5"),
    ("e071a3f6c06f", "bignum.h", "c946d2678051772a771ec2ba9c33fee64d8c1d0c92b6a791d6637ba673b36fc0"),
    ("e071a3f6c06f", "key.h", "f631451db96081b0eeb4ca74d2f9c221de934f1079b166077055f4d0cea63e68"),
    ("e071a3f6c06f", "main.h", "bebb0c557b39bd0a1222ef33a6f44c2ef4379bb4e1f0e9f6c1f5549dcc31c748"),
    ("e071a3f6c06f", "main.cpp", "d4b5e415e4d3c53c18afc3837ff78a2da4eecb4b724f4aa1b2894a0a2d2fb983"),
    ("e071a3f6c06f", "serialize.h", "f946aaa4851c6dbfb13200a6331152c2cae11e0ffc03378476ee20d82bbb1f15"),
    ("e071a3f6c06f", "util.h", "1411b8f3ff7c712ea80f98587e3b8a9cf05b81a1dc8c45021bbf491de6292534"),
    ("e071a3f6c06f", "uint256.h", "54818c679957094352ca5a6d7b7d131cfa7052ee54d8481053f87f57217b0c59"),
    # 0.1.6 — 29 October 2009: time-based nLockTime; finality becomes a block rule
    ("dd519206a684", "main.h", "07b626d1c6d2a51b33674eac30cb1ce3e7f5f1ed6508dfb287cceb180424388c"),
    ("dd519206a684", "main.cpp", "039362df9eacc3ae462c613affbf753b1168f2d52d0341daf2d2118999eb6d34"),
    # 0.3.6 — 29 July 2010: OP_RETURN fails; size limits introduced
    ("757f0769d836", "script.h", "0dd9ff58945f5ebcf830c8510d8d33b63f0afe931448600e60dc4221001504f6"),
    ("757f0769d836", "script.cpp", "3ea783023a6fcc6773a556f35c1ac7289e93efe28b87784e8f864834122d2dc1"),
    ("757f0769d836", "serialize.h", "64dddb25483d1506ab408925f8417868d0ee9e7de2a0d40ef082d94f274a9258"),
    ("757f0769d836", "main.h", "2ffe951fa966b894b406d2699fab140bd9a20c8a9fa4d820541d9115e0fa4142"),
    ("757f0769d836", "main.cpp", "c3b3768ad3dc77b74b9102a242961f7f048dda3684d73eb0261e645f63f6b225"),
    # 15 August 2010, "misc changes": fifteen opcodes disabled; 4-byte numbers
    ("4bd188c4383d", "script.h", "7177c5d46d1b54a8351a1faa0c841358c1978ce580f99dfeaf5b369038244a58"),
    ("4bd188c4383d", "script.cpp", "40093dbe313feffcc946dfba2cd969deecc665a80cd60fdc2ddfd89486774e6d"),
    ("4bd188c4383d", "serialize.h", "d0e7b14033bde312f503ee59bae4b2f26bf1bebfc8b8d543f8021fd4c81b2af4"),
    # 7 December 2010: IsStandard() relay policy
    ("a206a23980c1", "script.h", "829311f4c18dfe6020eaeda0cc14ee38f194916b4de6c2ddba5ba20443d11594"),
    ("a206a23980c1", "script.cpp", "8ebacee106954d9d8112fd0a7e457621b75204e8c7813423ac75c0ffa0fae380"),
    ("a206a23980c1", "serialize.h", "a6c758ccd53183c0934cf2b1dc7494dc807513b65bd63f117295a110e6e93ca1"),
    ("a206a23980c1", "main.h", "720557d351a2545ebc5663b8fd4291ccc465134a18168cce1ce93ead6408ced8"),
    ("a206a23980c1", "main.cpp", "67baee7a14ca95936bcaa9aad5c3e408b6f6a5b6ce8515f2f7c97139d94a84a5"),
]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    bad = 0
    for commit, path, want in SOURCES:
        url = "%s/%s/%s" % (REPO, commit, path)
        data = urllib.request.urlopen(url, timeout=60).read()
        got = hashlib.sha256(data).hexdigest()
        ok = got == want
        print(("ok   " if ok else "FAIL ") + commit + "/" + path + ("" if ok else " " + got))
        if not ok:
            bad += 1
            continue
        out = os.path.join(here, "sources", commit, path)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "wb") as fh:
            fh.write(data)
    print("\n%d of %d verified" % (len(SOURCES) - bad, len(SOURCES)))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
