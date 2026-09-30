"""Install pinned official Linux CLI releases; verify each upstream checksum."""
import hashlib
import io
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path


TOOLS = [
    ('projectdiscovery/subfinder', 'v2.16.0', 'subfinder_2.16.0_linux_amd64.zip', 'subfinder_2.16.0_checksums.txt', 'subfinder', 'subfinder'),
    ('projectdiscovery/katana', 'v1.7.0', 'katana_1.7.0_linux_amd64.zip', 'katana-1.7.0-checksums.txt', 'katana', 'katana'),
    ('projectdiscovery/httpx', 'v1.12.0', 'httpx_1.12.0_linux_amd64.zip', 'httpx_1.12.0_checksums.txt', 'httpx', 'httpx-toolkit'),
    ('projectdiscovery/nuclei', 'v3.11.1', 'nuclei_3.11.1_linux_amd64.zip', 'nuclei_3.11.1_checksums.txt', 'nuclei', 'nuclei'),
    ('lc/gau', 'v2.2.4', 'gau_2.2.4_linux_amd64.tar.gz', 'gau_2.2.4_checksums.txt', 'gau', 'gau'),
    ('gitleaks/gitleaks', 'v8.30.1', 'gitleaks_8.30.1_linux_x64.tar.gz', 'gitleaks_8.30.1_checksums.txt', 'gitleaks', 'gitleaks'),
]


def download(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'BLH-Hunter-build'})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def main():
    if platform.machine() not in {'x86_64', 'amd64'}:
        raise RuntimeError('Pinned deployment images currently support linux/amd64')
    output = Path('/opt/recon')
    output.mkdir(parents=True, exist_ok=True)
    for repo, tag, asset, checksum_file, member, name in TOOLS:
        base = f'https://github.com/{repo}/releases/download/{tag}'
        manifest = download(f'{base}/{checksum_file}').decode()
        expected = next(line.split()[0] for line in manifest.splitlines()
                        if len(line.split()) == 2 and line.split()[1].lstrip('*') == asset)
        data = download(f'{base}/{asset}')
        if hashlib.sha256(data).hexdigest() != expected:
            raise RuntimeError(f'Checksum mismatch: {asset}')
        if asset.endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                binary = archive.read(member)
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                binary = archive.extractfile(member).read()
        target = output / name
        target.write_bytes(binary)
        target.chmod(0o755)
        print(f'Installed {name} {tag} (checksum verified)', flush=True)


if __name__ == '__main__':
    main()
