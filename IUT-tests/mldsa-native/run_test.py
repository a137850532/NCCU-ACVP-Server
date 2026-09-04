#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib
import importlib.abc
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]

SUPPORTED_MODES = {"keyGen", "sigGen", "sigVer"}
SUPPORTED_IDENTITIES = {
    ("ML-DSA", "keyGen", "FIPS204"),
    ("ML-DSA", "sigGen", "FIPS204"),
    ("ML-DSA", "sigGen", "FIPS204-tr1"),
    ("ML-DSA", "sigVer", "FIPS204"),
}
PARAMETER_OBJECTS = {
    "ML-DSA-44": "ML_DSA_44",
    "ML-DSA-65": "ML_DSA_65",
    "ML-DSA-87": "ML_DSA_87",
}
FALLBACK_VERIFY_PARAMETERS = {
    "ML-DSA-44": "ML_DSA_44",
    "ML-DSA-65": "ML_DSA_65",
    "ML-DSA-87": "ML_DSA_87",
}

HASH_OIDS = {
    "SHA2-224": bytes.fromhex("0609608648016503040204"),
    "SHA2-256": bytes.fromhex("0609608648016503040201"),
    "SHA2-384": bytes.fromhex("0609608648016503040202"),
    "SHA2-512": bytes.fromhex("0609608648016503040203"),
    "SHA2-512/224": bytes.fromhex("0609608648016503040205"),
    "SHA2-512/256": bytes.fromhex("0609608648016503040206"),
    "SHA3-224": bytes.fromhex("0609608648016503040207"),
    "SHA3-256": bytes.fromhex("0609608648016503040208"),
    "SHA3-384": bytes.fromhex("0609608648016503040209"),
    "SHA3-512": bytes.fromhex("060960864801650304020A"),
    "SHAKE-128": bytes.fromhex("060960864801650304020B"),
    "SHAKE-256": bytes.fromhex("060960864801650304020C"),
}


class IutRunnerError(RuntimeError):
    pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate ML-DSA ACVP IUT response JSON from prompt JSON.",
    )
    parser.add_argument(
        "--prompt",
        default=str(SCRIPT_DIR / "prompt.json"),
        help="Path to ACVP prompt JSON. Default: ./prompt.json",
    )
    parser.add_argument(
        "--response-dir",
        default=str(SCRIPT_DIR / "response"),
        help="Directory for response_pass_<mode>.json and response_fail_<mode>.json.",
    )
    parser.add_argument(
        "--variant",
        choices=("pass", "fail", "both"),
        default="both",
        help="Which response fixture to write.",
    )
    parser.add_argument(
        "--expect-mode",
        choices=tuple(sorted(SUPPORTED_MODES)),
        help="Fail if the prompt mode does not match this value.",
    )
    parser.add_argument(
        "--dilithium-py-src",
        default=os.environ.get("DILITHIUM_PY_SRC"),
        help=(
            "Optional path to a GiacomoPope/dilithium-py checkout or its src/ "
            "directory. Used when the package is not installed."
        ),
    )
    parser.add_argument(
        "--mldsa-py-src",
        default=os.environ.get("MLDSA_PY_SRC"),
        help=(
            "Optional path to a FiloSottile/mldsa-py checkout or its src/ "
            "directory. Limited fallback for sigVer only."
        ),
    )
    args = parser.parse_args(argv)

    try:
        prompt_path = Path(args.prompt)
        response_dir = Path(args.response_dir)
        prompt = _read_json(prompt_path)
        vector_set = _acvp_body(prompt)
        algorithm = _required_string(vector_set, "algorithm", "$.algorithm")
        mode = _required_string(vector_set, "mode", "$.mode")
        revision = _required_string(vector_set, "revision", "$.revision")
        _require_supported_identity(algorithm, mode, revision)
        if args.expect_mode and mode != args.expect_mode:
            raise IutRunnerError(
                f"prompt mode {mode!r} does not match expected mode {args.expect_mode!r}"
            )

        response_dir.mkdir(parents=True, exist_ok=True)
        crypto = _load_crypto(args.dilithium_py_src, args.mldsa_py_src)
        pass_response = _generate_response(vector_set, crypto)

        pass_output = response_dir / f"response_pass_{mode}.json"
        fail_output = response_dir / f"response_fail_{mode}.json"

        written = []
        if args.variant in {"pass", "both"}:
            written.append(_write_json(pass_output, pass_response))
        if args.variant in {"fail", "both"}:
            fail_response = copy.deepcopy(pass_response)
            _mutate_first_result(fail_response, mode)
            written.append(_write_json(fail_output, fail_response))

        for path in written:
            print(path)
        return 0
    except Exception as exc:  # pragma: no cover - script-level failure path
        print(f"error: {exc}", file=sys.stderr)
        return 1


class CryptoBackend:
    def __init__(self, dilithium_module: Any = None, mldsa_module: Any = None):
        self.dilithium_module = dilithium_module
        self.mldsa_module = mldsa_module

    @property
    def has_dilithium(self) -> bool:
        return self.dilithium_module is not None

    @property
    def has_verify_fallback(self) -> bool:
        return self.mldsa_module is not None

    def parameter(self, parameter_set: str) -> Any:
        if self.dilithium_module is None:
            raise IutRunnerError(
                "keyGen and sigGen require GiacomoPope/dilithium-py. "
                "Install it with Python 3.9+ or pass --dilithium-py-src."
            )
        name = PARAMETER_OBJECTS.get(parameter_set)
        if name is None:
            raise IutRunnerError(f"unsupported parameterSet: {parameter_set!r}")
        return getattr(self.dilithium_module, name)

    def verify_with_fallback(
        self,
        parameter_set: str,
        pk: bytes,
        message: bytes,
        signature: bytes,
        context: bytes,
    ) -> bool:
        if self.mldsa_module is None:
            raise IutRunnerError("mldsa-py fallback is not available")
        params_name = FALLBACK_VERIFY_PARAMETERS.get(parameter_set)
        if params_name is None:
            raise IutRunnerError(f"unsupported parameterSet: {parameter_set!r}")
        params = getattr(self.mldsa_module.Parameters, params_name)
        vk = self.mldsa_module.VerificationKey(pk, parameters=params)
        try:
            vk.verify(message, signature, context=context)
            return True
        except self.mldsa_module.VerificationError:
            return False


def _load_crypto(dilithium_src: Optional[str], mldsa_src: Optional[str]) -> CryptoBackend:
    dilithium_module = _import_dilithium_py(dilithium_src)
    mldsa_module = None
    if dilithium_module is None:
        mldsa_module = _import_mldsa_py(mldsa_src)
    if dilithium_module is None and mldsa_module is None:
        raise IutRunnerError(
            "No ML-DSA implementation is available. Preferred: clone "
            "https://github.com/GiacomoPope/dilithium-py and pass "
            "--dilithium-py-src /path/to/dilithium-py/src. Fallback for sigVer "
            "only: clone https://github.com/FiloSottile/mldsa-py and pass "
            "--mldsa-py-src /path/to/mldsa-py/src."
        )
    return CryptoBackend(dilithium_module=dilithium_module, mldsa_module=mldsa_module)


def _import_dilithium_py(source_arg: Optional[str]) -> Any:
    try:
        return importlib.import_module("dilithium_py.ml_dsa")
    except Exception:
        _purge_modules("dilithium_py")

    for candidate in _source_candidates(
        source_arg,
        "dilithium_py",
        [
            REPO_ROOT / "third_party" / "dilithium-py",
            REPO_ROOT / "third_party" / "dilithium-py" / "src",
            SCRIPT_DIR / "dilithium-py",
            SCRIPT_DIR / "dilithium-py" / "src",
            Path("/tmp/dilithium-py-source"),
            Path("/tmp/dilithium-py-source/src"),
        ],
    ):
        candidate_text = str(candidate)

        if candidate_text not in sys.path:
            sys.path.insert(0, candidate_text)

        try:
            return importlib.import_module("dilithium_py.ml_dsa")
        except Exception:
            _purge_modules("dilithium_py")
            continue

    return None

def _import_mldsa_py(source_arg: Optional[str]) -> Any:
    try:
        return importlib.import_module("mldsa")
    except Exception:
        _purge_modules("mldsa")

    for candidate in _source_candidates(
        source_arg,
        "mldsa",
        [
            REPO_ROOT / "third_party" / "mldsa-py",
            REPO_ROOT / "third_party" / "mldsa-py" / "src",
            SCRIPT_DIR / "mldsa-py",
            SCRIPT_DIR / "mldsa-py" / "src",
            Path("/tmp/mldsa-py-source"),
            Path("/tmp/mldsa-py-source/src"),
        ],
    ):
        if str(candidate) not in sys.path:
            sys.path.insert(0, str(candidate))
        try:
            return importlib.import_module("mldsa")
        except Exception:
            _purge_modules("mldsa")
            continue
    return None


def _source_candidates(
    explicit: Optional[str],
    package: str,
    defaults: Iterable[Path],
) -> Iterable[Path]:
    values = []
    if explicit:
        values.append(Path(explicit))
    values.extend(defaults)
    seen = set()
    for value in values:
        source = _normalize_source_path(value, package)
        if source is None:
            continue
        key = str(source.resolve())
        if key in seen:
            continue
        seen.add(key)
        yield source


def _normalize_source_path(path: Path, package: str) -> Optional[Path]:
    expanded = path.expanduser()
    if (expanded / package / "__init__.py").exists():
        return expanded
    if (expanded / "src" / package / "__init__.py").exists():
        return expanded / "src"
    return None


class _FutureAnnotationsLoader(importlib.abc.SourceLoader):
    def __init__(self, fullname: str, path: Path):
        self.fullname = fullname
        self.path = path

    def get_filename(self, fullname: str) -> str:
        return str(self.path)

    def get_data(self, path: str) -> bytes:
        data = Path(path).read_bytes()
        if path.endswith(".py") and b"from __future__ import annotations" not in data[:200]:
            data = b"from __future__ import annotations\n" + data
        return data


class _FutureAnnotationsFinder(importlib.abc.MetaPathFinder):
    def __init__(self, package: str, root: Path):
        self.package = package
        self.root = root

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
        if fullname != self.package and not fullname.startswith(f"{self.package}."):
            return None
        parts = fullname.split(".")
        package_path = self.root.joinpath(*parts, "__init__.py")
        module_path = self.root.joinpath(*parts).with_suffix(".py")
        if package_path.exists():
            return importlib.util.spec_from_loader(
                fullname,
                _FutureAnnotationsLoader(fullname, package_path),
                origin=str(package_path),
                is_package=True,
            )
        if module_path.exists():
            return importlib.util.spec_from_loader(
                fullname,
                _FutureAnnotationsLoader(fullname, module_path),
                origin=str(module_path),
            )
        return None


def _install_future_annotations_importer(package: str, source_root: Path) -> None:
    for finder in list(sys.meta_path):
        if (
            isinstance(finder, _FutureAnnotationsFinder)
            and finder.package == package
            and finder.root == source_root
        ):
            return
    sys.meta_path.insert(0, _FutureAnnotationsFinder(package, source_root))


def _purge_modules(prefix: str) -> None:
    for name in list(sys.modules):
        if name == prefix or name.startswith(f"{prefix}."):
            sys.modules.pop(name, None)


def _generate_response(vector_set: Dict[str, Any], crypto: CryptoBackend) -> Dict[str, Any]:
    mode = _required_string(vector_set, "mode", "$.mode")
    revision = _required_string(vector_set, "revision", "$.revision")
    body: Dict[str, Any] = {
        "vsId": vector_set.get("vsId"),
        "algorithm": vector_set.get("algorithm", "ML-DSA"),
        "mode": mode,
        "revision": revision,
        "testGroups": [],
    }
    groups = vector_set.get("testGroups")
    if not isinstance(groups, list):
        raise IutRunnerError("$.testGroups must be an array")
    for group_index, group in enumerate(groups):
        if not isinstance(group, dict):
            raise IutRunnerError(f"$.testGroups[{group_index}] must be an object")
        parameter_set = _required_string(group, "parameterSet", f"$.testGroups[{group_index}].parameterSet")
        tg_id = group.get("tgId")
        response_group = {"tgId": tg_id, "tests": []}
        tests = group.get("tests")
        if not isinstance(tests, list):
            raise IutRunnerError(f"$.testGroups[{group_index}].tests must be an array")
        for test_index, test in enumerate(tests):
            if not isinstance(test, dict):
                raise IutRunnerError(
                    f"$.testGroups[{group_index}].tests[{test_index}] must be an object"
                )
            response_group["tests"].append(
                _generate_test_response(
                    mode, revision, parameter_set, group, test, crypto
                )
            )
        body["testGroups"].append(response_group)
    return body


def _generate_test_response(
    mode: str,
    revision: str,
    parameter_set: str,
    group: Dict[str, Any],
    test: Dict[str, Any],
    crypto: CryptoBackend,
) -> Dict[str, Any]:
    tc_id = test.get("tcId")
    if mode == "keyGen":
        ml_dsa = crypto.parameter(parameter_set)
        seed = _hex_bytes(_required_string(test, "seed", "$.seed"), "seed", expected_len=32)
        pk, sk = ml_dsa.key_derive(seed)
        return {"tcId": tc_id, "pk": pk.hex().upper(), "sk": sk.hex().upper()}

    if mode == "sigGen":
        ml_dsa = crypto.parameter(parameter_set)
        key_format = str(group.get("keyFormat", "expanded"))
        if revision == "FIPS204-tr1" and key_format == "seed":
            seed = _hex_bytes(
                _required_lookup(test, group, "seed"), "seed", expected_len=32
            )
            _pk, sk = ml_dsa.key_derive(seed)
        elif key_format == "expanded":
            sk = _hex_bytes(_required_lookup(test, group, "sk"), "sk")
        else:
            raise IutRunnerError(
                f"unsupported ML-DSA sigGen keyFormat: {key_format!r}"
            )
        signature = _sign_test(ml_dsa, group, test, sk)
        return {"tcId": tc_id, "signature": signature.hex().upper()}

    if mode == "sigVer":
        test_passed = _verify_test(parameter_set, group, test, crypto)
        return {"tcId": tc_id, "testPassed": test_passed}

    raise IutRunnerError(f"unsupported ML-DSA mode: {mode!r}")


def _sign_test(
    ml_dsa: Any, group: Dict[str, Any], test: Dict[str, Any], sk: bytes
) -> bytes:
    deterministic = bool(group.get("deterministic", True))
    rnd = _signing_rnd(test, deterministic)
    signature_interface = str(group.get("signatureInterface", "internal"))
    external_mu = bool(group.get("externalMu", False))
    if external_mu:
        mu = _hex_bytes(_required_lookup(test, group, "mu"), "mu", expected_len=64)
        return ml_dsa._sign_internal(sk, mu, rnd, external_mu=True)

    message = _hex_bytes(_required_lookup(test, group, "message"), "message")
    if signature_interface == "external":
        return ml_dsa._sign_internal(sk, _formatted_message(group, test, message), rnd)
    return ml_dsa._sign_internal(sk, message, rnd)


def _require_supported_identity(algorithm: str, mode: str, revision: str) -> None:
    identity = (algorithm, mode, revision)
    if identity not in SUPPORTED_IDENTITIES:
        raise IutRunnerError(
            "unsupported ML-DSA algorithm/mode/revision identity: "
            f"{algorithm}/{mode}/{revision}"
        )


def _verify_test(
    parameter_set: str,
    group: Dict[str, Any],
    test: Dict[str, Any],
    crypto: CryptoBackend,
) -> bool:
    pk = _hex_bytes(_required_lookup(test, group, "pk"), "pk")
    signature = _hex_bytes(_required_lookup(test, group, "signature"), "signature")
    external_mu = bool(group.get("externalMu", False))

    if crypto.has_dilithium:
        ml_dsa = crypto.parameter(parameter_set)
        if external_mu:
            mu = _hex_bytes(_required_lookup(test, group, "mu"), "mu", expected_len=64)
            return _verify_internal(ml_dsa, pk, mu, signature, external_mu=True)
        message = _hex_bytes(_required_lookup(test, group, "message"), "message")
        if str(group.get("signatureInterface", "internal")) == "external":
            return _verify_internal(
                ml_dsa,
                pk,
                _formatted_message(group, test, message),
                signature,
            )
        return _verify_internal(ml_dsa, pk, message, signature)

    if (
        str(group.get("signatureInterface", "internal")) != "external"
        or external_mu
        or _is_prehash(group.get("preHash", "pure"))
    ):
        raise IutRunnerError(
            "mldsa-py fallback supports only external pure message sigVer, "
            "not internal, externalMu, or preHash"
        )
    message = _hex_bytes(_required_lookup(test, group, "message"), "message")
    context = _context_bytes(test, group)
    return crypto.verify_with_fallback(parameter_set, pk, message, signature, context)


def _verify_internal(
    ml_dsa: Any,
    pk: bytes,
    m_prime_or_mu: bytes,
    sig: bytes,
    *,
    external_mu: bool = False,
) -> bool:
    try:
        rho, t1 = ml_dsa._unpack_pk(pk)
        c_tilde, z, h = ml_dsa._unpack_sig(sig)
    except ValueError:
        return False

    if h.sum_hint() > ml_dsa.omega:
        return False
    if z.check_norm_bound(ml_dsa.gamma_1 - ml_dsa.beta):
        return False

    a_hat = ml_dsa._expand_matrix_from_seed(rho)
    if external_mu:
        mu = m_prime_or_mu
    else:
        tr = ml_dsa._h(pk, 64)
        mu = ml_dsa._h(tr + m_prime_or_mu, 64)
    c = ml_dsa.R.sample_in_ball(c_tilde, ml_dsa.tau).to_ntt()
    z = z.to_ntt()
    t1 = t1.scale(1 << ml_dsa.d).to_ntt()
    az_minus_ct1 = (a_hat @ z) - t1.scale(c)
    az_minus_ct1 = az_minus_ct1.from_ntt()
    w_prime = h.use_hint(az_minus_ct1, 2 * ml_dsa.gamma_2)
    w_prime_bytes = w_prime.bit_pack_w(ml_dsa.gamma_2)
    return c_tilde == ml_dsa._h(mu + w_prime_bytes, ml_dsa.c_tilde_bytes)


def _formatted_message(group: Dict[str, Any], test: Dict[str, Any], message: bytes) -> bytes:
    context = _context_bytes(test, group)
    if _is_prehash(group.get("preHash", "pure")):
        hash_alg = _required_lookup(test, group, "hashAlg")
        oid = HASH_OIDS.get(str(hash_alg).upper())
        if oid is None:
            raise IutRunnerError(f"unsupported hashAlg for preHash: {hash_alg!r}")
        digest = _hash_message(message, str(hash_alg))
        return bytes([1, len(context)]) + context + oid + digest
    return bytes([0, len(context)]) + context + message


def _hash_message(message: bytes, hash_alg: str) -> bytes:
    normalized = hash_alg.upper()
    if normalized == "SHA2-224":
        return hashlib.sha224(message).digest()
    if normalized == "SHA2-256":
        return hashlib.sha256(message).digest()
    if normalized == "SHA2-384":
        return hashlib.sha384(message).digest()
    if normalized == "SHA2-512":
        return hashlib.sha512(message).digest()
    if normalized == "SHA2-512/224":
        return hashlib.new("sha512_224", message).digest()
    if normalized == "SHA2-512/256":
        return hashlib.new("sha512_256", message).digest()
    if normalized == "SHA3-224":
        return hashlib.sha3_224(message).digest()
    if normalized == "SHA3-256":
        return hashlib.sha3_256(message).digest()
    if normalized == "SHA3-384":
        return hashlib.sha3_384(message).digest()
    if normalized == "SHA3-512":
        return hashlib.sha3_512(message).digest()
    if normalized == "SHAKE-128":
        return hashlib.shake_128(message).digest(32)
    if normalized == "SHAKE-256":
        return hashlib.shake_256(message).digest(64)
    raise IutRunnerError(f"unsupported hashAlg: {hash_alg!r}")


def _context_bytes(test: Dict[str, Any], group: Dict[str, Any]) -> bytes:
    value = test.get("context", group.get("context", ""))
    if value is None:
        value = ""
    context = _hex_bytes(str(value), "context")
    if len(context) > 255:
        raise IutRunnerError("context must be at most 255 bytes")
    return context


def _signing_rnd(test: Dict[str, Any], deterministic: bool) -> bytes:
    if "rnd" in test:
        return _hex_bytes(str(test["rnd"]), "rnd", expected_len=32)
    if deterministic:
        return bytes(32)
    raise IutRunnerError("randomized sigGen test is missing rnd")


def _is_prehash(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"prehash", "hash", "true", "1"}


def _read_json(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"prompt JSON not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: Any) -> Path:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")
    return path


def _acvp_body(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        if "prompt" in payload and isinstance(payload["prompt"], dict):
            return payload["prompt"]
        return payload
    if isinstance(payload, list):
        for item in payload[1:]:
            if isinstance(item, dict) and "testGroups" in item:
                return item
    raise IutRunnerError("prompt payload does not contain an ACVP vector set body")


def _required_string(body: Dict[str, Any], field: str, path: str) -> str:
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise IutRunnerError(f"{path} must be a non-empty string")
    return value


def _required_lookup(test: Dict[str, Any], group: Dict[str, Any], field: str) -> Any:
    if field in test:
        return test[field]
    if field in group:
        return group[field]
    raise IutRunnerError(f"missing required field {field!r}")


def _hex_bytes(value: str, name: str, expected_len: Optional[int] = None) -> bytes:
    if not isinstance(value, str):
        raise IutRunnerError(f"{name} must be a hex string")
    if len(value) % 2:
        raise IutRunnerError(f"{name} must be even-length hex")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as exc:
        raise IutRunnerError(f"{name} must contain only hex characters") from exc
    if expected_len is not None and len(decoded) != expected_len:
        raise IutRunnerError(f"{name} must be {expected_len} bytes")
    return decoded


def _response_body(payload: Any) -> Dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, list):
        for item in payload[1:]:
            if isinstance(item, dict) and "testGroups" in item:
                return item
    raise IutRunnerError("response payload does not contain an ACVP response body")


def _first_test(body: Dict[str, Any]) -> Dict[str, Any]:
    groups = body.get("testGroups")
    if not isinstance(groups, list) or not groups:
        raise IutRunnerError("response body has no testGroups")
    tests = groups[0].get("tests")
    if not isinstance(tests, list) or not tests:
        raise IutRunnerError("response body has no tests")
    first = tests[0]
    if not isinstance(first, dict):
        raise IutRunnerError("first response test is not an object")
    return first


def _mutate_first_result(payload: Any, mode: str) -> None:
    body = _response_body(payload)
    test = _first_test(body)
    if mode == "keyGen":
        _mutate_hex_field(test, "pk")
        return
    if mode == "sigGen":
        _mutate_hex_field(test, "signature")
        return
    if mode == "sigVer":
        if "testPassed" not in test or not isinstance(test["testPassed"], bool):
            raise IutRunnerError("sigVer response has no boolean testPassed field to mutate")
        test["testPassed"] = not test["testPassed"]
        return
    raise IutRunnerError(f"unsupported ML-DSA mode: {mode!r}")


def _mutate_hex_field(test: Dict[str, Any], field: str) -> None:
    value = test.get(field)
    if not isinstance(value, str) or not value:
        raise IutRunnerError(f"response test has no hex {field!r} field to mutate")
    replacement = "1" if value[0].upper() == "0" else "0"
    test[field] = f"{replacement}{value[1:]}"


if __name__ == "__main__":
    raise SystemExit(main())
