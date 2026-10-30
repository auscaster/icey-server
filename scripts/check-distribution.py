#!/usr/bin/env python3
"""Read back the public Icey and Icey Server release surfaces."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
PINNED_LIBRARY_VERSION = (ROOT / "ICEY_VERSION").read_text().strip()
SERVER_VERSION = (ROOT / "VERSION").read_text().strip()
HOMEPAGE = "https://auscaster.com/icey"
HEADERS = {"User-Agent": "icey-release-audit/1.0"}


def fetch(url):
    try:
        headers = dict(HEADERS)
        image = re.match(r"https://ghcr\.io/v2/(auscaster/(?:icey|icey-server))/", url)
        if image:
            # Public GHCR pulls still require an anonymous, pull-only bearer grant.
            token_url = f"https://ghcr.io/token?service=ghcr.io&scope=repository:{image.group(1)}:pull"
            with urlopen(Request(token_url, headers=HEADERS), timeout=20) as response:
                headers["Authorization"] = "Bearer " + json.load(response)["token"]
            headers["Accept"] = "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
        with urlopen(Request(url, headers=headers), timeout=20) as response:
            payload = response.read()
            return (gzip.decompress(payload) if url.endswith(".gz") else payload).decode(), None
    except HTTPError as error:
        return None, f"HTTP {error.code}"
    except (URLError, TimeoutError) as error:
        return None, str(error)


def version_in(pattern, body):
    match = re.search(pattern, body, re.MULTILINE)
    return match.group(1) if match else None


def check(surface):
    name, owner, expected, url, extract = surface
    body, error = fetch(url)
    if error:
        return dict(name=name, owner=owner, expected=expected, live=None,
                    status="missing" if error == "HTTP 404" else "unknown",
                    url=url, detail=error)
    try:
        live = extract(body)
    except (KeyError, TypeError, ValueError, OSError, subprocess.CalledProcessError,
            tarfile.TarError) as error:
        return dict(name=name, owner=owner, expected=expected, live=None,
                    status="unknown", url=url, detail=str(error))
    status = "current" if live == expected else "stale" if live else "missing"
    return dict(name=name, owner=owner, expected=expected, live=live,
                status=status, url=url)


def github_release_version(body):
    return json.loads(body)["tag_name"].removeprefix("v")


def server_assets(body):
    names = {asset["name"] for asset in json.loads(body)["assets"]}
    required = {
        f"icey-server-{SERVER_VERSION}-source.tar.gz",
        f"icey-{PINNED_LIBRARY_VERSION}-source.tar.gz",
        f"icey-server-{SERVER_VERSION}-Linux-x86_64.tar.gz",
        f"icey-server_{SERVER_VERSION}_amd64.deb",
    }
    return SERVER_VERSION if required <= names else ", ".join(sorted(required - names))


def ghcr_labels(body, image):
    digest = json.loads(body)["config"]["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("Invalid container config digest")
    config, error = fetch(f"https://ghcr.io/v2/auscaster/{image}/blobs/{digest}")
    if error:
        raise ValueError(f"Container config unavailable: {error}")
    if hashlib.sha256(config.encode()).hexdigest() != digest.removeprefix("sha256:"):
        raise ValueError("Container config checksum does not match manifest")
    return json.loads(config)["config"]["Labels"]


def aur_version(package):
    def extract(body):
        matches = [row for row in json.loads(body)["results"] if row["Name"] == package]
        return matches[0]["Version"].split("-", 1)[0] if matches else None
    return extract


def aur_homepage(package):
    def extract(body):
        matches = [row for row in json.loads(body)["results"] if row["Name"] == package]
        return matches[0]["URL"].rstrip("/") if matches else None
    return extract


def docker_homepage(body):
    description = json.loads(body).get("full_description") or ""
    return (version_in(r"\[Project homepage\]\((https?://[^)]+)\)", description) or "").rstrip("/")


def ppa_binary_version(body):
    entries = json.loads(body)["entries"]
    return entries[0]["binary_package_version"].split("-", 1)[0] if entries else None


def apt_version(body):
    return version_in(r"^Package: icey-server\nVersion: (\S+)", body)


def deb_homepage(url, expected_sha256):
    with urlopen(Request(url, headers=HEADERS), timeout=20) as response:
        payload = response.read()
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError("PPA binary checksum does not match package index")
    with tempfile.NamedTemporaryFile(suffix=".deb") as deb:
        deb.write(payload)
        deb.flush()
        if shutil.which("dpkg-deb"):
            result = subprocess.run(["dpkg-deb", "-f", deb.name, "Homepage"],
                                    capture_output=True, text=True, check=True)
            return result.stdout.strip().rstrip("/")

        members = subprocess.run(["ar", "t", deb.name], capture_output=True,
                                 text=True, check=True).stdout.splitlines()
        control_name = next((name for name in members if name.startswith("control.tar.")), None)
        if not control_name:
            raise ValueError("Debian control archive not found")
        archive = subprocess.run(["ar", "p", deb.name, control_name],
                                 capture_output=True, check=True).stdout
        if control_name.endswith(".zst"):
            archive = subprocess.run(["zstd", "-dc"], input=archive,
                                     capture_output=True, check=True).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as control:
            body = control.extractfile("./control").read().decode()
        return (version_in(r"^Homepage: (\S+)", body) or "").rstrip("/")


def apt_package_homepage(package, expected_version=None, inspect_binary=False):
    def extract(body):
        for stanza in body.split("\n\n"):
            if version_in(r"^Package: (\S+)", stanza) == package:
                if inspect_binary and (version_in(r"^Version: (\S+)", stanza) or "").split("-", 1)[0] != expected_version:
                    raise ValueError(f"{package} PPA index has not reached {expected_version}")
                homepage = (version_in(r"^Homepage: (\S+)", stanza) or "").rstrip("/")
                if homepage or not inspect_binary:
                    return homepage
                filename = version_in(r"^Filename: (\S+)", stanza)
                sha256 = version_in(r"^SHA256: (\S+)", stanza)
                if not filename or not sha256:
                    raise ValueError(f"{package} PPA index lacks Filename or SHA256")
                return deb_homepage(f"https://ppa.launchpadcontent.net/0state/icey/ubuntu/{filename}", sha256)
        return None
    return extract


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="fail when an owned release surface drifts")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args()

    # ICEY_VERSION pins the source bundled with this server. Independently
    # published library channels follow the library's own latest release.
    library_release = "https://api.github.com/repos/auscaster/icey/releases/latest"
    body, error = fetch(library_release)
    if error:
        parser.exit(1, f"Cannot resolve published Icey release: {error}\n")
    library_version = github_release_version(body)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", library_version):
        parser.exit(1, "Published Icey release has an invalid version\n")

    # Docker Hub mirrors must preserve the exact public GHCR release manifest.
    image_digests = {}
    for image, version in (("icey", library_version), ("icey-server", SERVER_VERSION)):
        manifest, error = fetch(f"https://ghcr.io/v2/auscaster/{image}/manifests/{version}")
        if error:
            parser.exit(1, f"Cannot resolve {image} release manifest: {error}\n")
        image_digests[image] = "sha256:" + hashlib.sha256(manifest.encode()).hexdigest()

    aur = "https://aur.archlinux.org/rpc/v5/info?arg[]=icey&arg[]=icey-server"
    surfaces = [
        ("Icey GitHub release", "owned", library_version,
         f"https://api.github.com/repos/auscaster/icey/releases/tags/{library_version}", github_release_version),
        ("Icey Server GitHub assets", "owned", SERVER_VERSION,
         f"https://api.github.com/repos/auscaster/icey-server/releases/tags/v{SERVER_VERSION}", server_assets),
        ("Icey container", "owned", library_version,
         f"https://ghcr.io/v2/auscaster/icey/manifests/{library_version}",
         lambda b: ghcr_labels(b, "icey").get("org.opencontainers.image.version")),
        ("Icey Server container", "owned", SERVER_VERSION,
         f"https://ghcr.io/v2/auscaster/icey-server/manifests/{SERVER_VERSION}",
         lambda b: ghcr_labels(b, "icey-server").get("org.opencontainers.image.version")),
        ("Icey GHCR latest manifest", "owned", image_digests["icey"],
         "https://ghcr.io/v2/auscaster/icey/manifests/latest",
         lambda b: "sha256:" + hashlib.sha256(b.encode()).hexdigest()),
        ("Icey Server GHCR latest manifest", "owned", image_digests["icey-server"],
         "https://ghcr.io/v2/auscaster/icey-server/manifests/latest",
         lambda b: "sha256:" + hashlib.sha256(b.encode()).hexdigest()),
        ("Icey Docker Hub latest mirror", "owned", image_digests["icey"],
         "https://hub.docker.com/v2/repositories/auscaster/icey/tags/latest/",
         lambda b: json.loads(b).get("digest")),
        ("Icey Server Docker Hub latest mirror", "owned", image_digests["icey-server"],
         "https://hub.docker.com/v2/repositories/auscaster/icey-server/tags/latest/",
         lambda b: json.loads(b).get("digest")),
        ("Icey Docker Hub mirror", "owned", image_digests["icey"],
         f"https://hub.docker.com/v2/repositories/auscaster/icey/tags/{library_version}/",
         lambda b: json.loads(b).get("digest")),
        ("Icey Server Docker Hub mirror", "owned", image_digests["icey-server"],
         f"https://hub.docker.com/v2/repositories/auscaster/icey-server/tags/{SERVER_VERSION}/",
         lambda b: json.loads(b).get("digest")),
        ("Icey Homebrew", "owned", library_version,
         "https://raw.githubusercontent.com/auscaster/homebrew-tap/main/Formula/icey.rb",
         lambda b: version_in(r'^  version "([^"]+)"', b)),
        ("Icey Server Homebrew", "owned", SERVER_VERSION,
         "https://raw.githubusercontent.com/auscaster/homebrew-tap/main/Formula/icey-server.rb",
         lambda b: version_in(r"/download/v([^/]+)/", b)),
        ("Icey AUR", "owned", library_version, aur, aur_version("icey")),
        ("Icey Server AUR", "owned", SERVER_VERSION, aur, aur_version("icey-server")),
        ("Icey Ubuntu PPA runtime", "owned", library_version,
         "https://api.launchpad.net/1.0/~0state/+archive/ubuntu/icey?ws.op=getPublishedBinaries&binary_name=libicey2&exact_match=true&status=Published", ppa_binary_version),
        ("Icey Ubuntu PPA development", "owned", library_version,
         "https://api.launchpad.net/1.0/~0state/+archive/ubuntu/icey?ws.op=getPublishedBinaries&binary_name=libicey-dev&exact_match=true&status=Published", ppa_binary_version),
        ("Icey Server APT", "owned", SERVER_VERSION,
         "https://apt.auscaster.com/icey/dists/stable/main/binary-amd64/Packages", apt_version),
        ("Icey openSUSE source", "owned", library_version,
         "https://src.opensuse.org/api/v1/repos/0state/icey/raw/icey.spec?ref=main",
         lambda b: version_in(r"^Version:\s+(\S+)", b)),
        ("Icey openSUSE service", "owned", library_version,
         "https://src.opensuse.org/api/v1/repos/0state/icey/raw/_service?ref=main",
         lambda b: version_in(r'<param name="revision">([^<]+)</param>', b)),
        ("Icey GitHub homepage", "owned", HOMEPAGE,
         "https://api.github.com/repos/auscaster/icey",
         lambda b: (json.loads(b).get("homepage") or "").rstrip("/")),
        ("Icey Server GitHub homepage", "owned", HOMEPAGE,
         "https://api.github.com/repos/auscaster/icey-server",
         lambda b: (json.loads(b).get("homepage") or "").rstrip("/")),
        ("Icey container homepage", "owned", HOMEPAGE,
         f"https://ghcr.io/v2/auscaster/icey/manifests/{library_version}",
         lambda b: (ghcr_labels(b, "icey").get("org.opencontainers.image.url") or "").rstrip("/")),
        ("Icey Docker Hub homepage", "owned", HOMEPAGE,
         "https://hub.docker.com/v2/repositories/auscaster/icey/", docker_homepage),
        ("Icey Server Docker Hub homepage", "owned", HOMEPAGE,
         "https://hub.docker.com/v2/repositories/auscaster/icey-server/", docker_homepage),
        ("Icey legacy Docker homepage", "owned", HOMEPAGE,
         "https://hub.docker.com/v2/repositories/0state/icey/", docker_homepage),
        ("Icey Server legacy Docker homepage", "owned", HOMEPAGE,
         "https://hub.docker.com/v2/repositories/0state/icey-server/", docker_homepage),
        ("Icey Server container homepage", "owned", HOMEPAGE,
         f"https://ghcr.io/v2/auscaster/icey-server/manifests/{SERVER_VERSION}",
         lambda b: (ghcr_labels(b, "icey-server").get("org.opencontainers.image.url") or "").rstrip("/")),
        ("Icey Homebrew homepage", "owned", HOMEPAGE,
         "https://raw.githubusercontent.com/auscaster/homebrew-tap/main/Formula/icey.rb",
         lambda b: (version_in(r'^  homepage "([^"]+)"', b) or "").rstrip("/")),
        ("Icey Server Homebrew homepage", "owned", HOMEPAGE,
         "https://raw.githubusercontent.com/auscaster/homebrew-tap/main/Formula/icey-server.rb",
         lambda b: (version_in(r'^  homepage "([^"]+)"', b) or "").rstrip("/")),
        ("Icey AUR homepage", "owned", HOMEPAGE, aur, aur_homepage("icey")),
        ("Icey Server AUR homepage", "owned", HOMEPAGE, aur, aur_homepage("icey-server")),
        ("Icey Server APT homepage", "owned", HOMEPAGE,
         "https://apt.auscaster.com/icey/dists/stable/main/binary-amd64/Packages",
         lambda b: (version_in(r'^Homepage: (\S+)', b) or "").rstrip("/")),
        ("Icey openSUSE homepage", "owned", HOMEPAGE,
         "https://src.opensuse.org/api/v1/repos/0state/icey/raw/icey.spec?ref=main",
         lambda b: (version_in(r"^URL:\s+(\S+)", b) or "").rstrip("/")),
        ("Icey Ubuntu PPA runtime homepage", "owned", HOMEPAGE,
         "https://ppa.launchpadcontent.net/0state/icey/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
         apt_package_homepage("libicey2", library_version, inspect_binary=True)),
        ("Icey Ubuntu PPA development homepage", "owned", HOMEPAGE,
         "https://ppa.launchpadcontent.net/0state/icey/ubuntu/dists/noble/main/binary-amd64/Packages.gz",
         apt_package_homepage("libicey-dev", library_version, inspect_binary=True)),
        ("Icey vcpkg", "upstream", library_version,
         "https://raw.githubusercontent.com/microsoft/vcpkg/master/ports/icey/vcpkg.json",
         lambda b: json.loads(b)["version"]),
        ("Icey ConanCenter", "upstream", library_version,
         "https://raw.githubusercontent.com/conan-io/conan-center-index/master/recipes/icey/config.yml",
         lambda b: version_in(r'^  "([0-9]+\.[0-9]+\.[0-9]+)":', b)),
        ("Icey MacPorts", "upstream", library_version,
         "https://raw.githubusercontent.com/macports/macports-ports/master/devel/icey/Portfile",
         lambda b: version_in(r'^github\.setup\s+\S+\s+icey\s+(\S+)', b)),
        ("Icey Spack", "upstream", library_version,
         "https://raw.githubusercontent.com/spack/spack-packages/develop/repos/spack_repo/builtin/packages/icey/package.py",
         lambda b: version_in(r'\bversion\("([0-9]+\.[0-9]+\.[0-9]+)"', b)),
        ("Icey Alpine", "upstream", library_version,
         "https://gitlab.alpinelinux.org/api/v4/projects/alpine%2Faports/repository/files/testing%2Ficey%2FAPKBUILD/raw?ref=master",
         lambda b: version_in(r'^pkgver=([0-9]+\.[0-9]+\.[0-9]+)', b)),
        ("Icey nixpkgs", "upstream", library_version,
         "https://raw.githubusercontent.com/NixOS/nixpkgs/master/pkgs/by-name/ic/icey/package.nix",
         lambda b: version_in(r'version\s*=\s*"([^"]+)"', b)),
        ("Icey conda-forge", "upstream", library_version,
         "https://api.anaconda.org/package/conda-forge/icey",
         lambda b: json.loads(b)["latest_version"]),
        ("Icey xrepo", "upstream", library_version,
         "https://raw.githubusercontent.com/xmake-io/xmake-repo/master/packages/i/icey/xmake.lua",
         lambda b: version_in(r'add_versions\("([^"]+)"', b)),
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(check, surfaces))

    # Rust bindings have their own version line; expose them without comparing
    # their semver to the C++ library version.
    bindings = []
    for name in ("icey", "icey-sys"):
        url = f"https://crates.io/api/v1/crates/{name}"
        body, error = fetch(url)
        crate = json.loads(body)["crate"] if body else {}
        homepage = (crate.get("homepage") or "").rstrip("/")
        bindings.append(dict(name=f"Rust {name}", owner="bindings",
                             live=crate.get("max_stable_version"),
                             status="listed" if body else "unknown", url=url,
                             detail=error))
        bindings.append(dict(name=f"Rust {name} homepage", owner="owned",
                             expected=HOMEPAGE, live=homepage or None,
                             status="current" if homepage == HOMEPAGE else "unknown" if error else "stale",
                             url=url, detail=error))
    results += bindings

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            print(f"{row['status']:8} {row['owner']:8} {row['name']:25} "
                  f"expected={row.get('expected', '-')} live={row.get('live') or '-'}")
    return int(args.strict and any(row["owner"] == "owned" and row["status"] != "current"
                                   for row in results))


if __name__ == "__main__":
    sys.exit(main())
