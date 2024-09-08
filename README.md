## Porkbun provider for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that targets [Porkbun](https://porkbun.com/).

### Installation

#### Command line

```
pip install octodns-porkbun
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-porkbun==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/loganlinn/octodns-porkbun.git@c58e70374e738cb13dd277b4fe99b0e26fcd94ef#egg=octodns_porkbun
```

### Configuration

```yaml
providers:
  porkbun:
    class: octodns_porkbun.PorkbunProvider
    api_key: env/PORKBUN_API_KEY
    secret_api_key: env/PORKBUN_SECRET_API_KEY
```

### Support Information

#### Records

PorkbunProvider supports A, AAAA, CAA, CNAME, MX, NS, TXT, and SRV

#### Root NS Records

PorkbunProvider supports full root NS record management.

#### Dynamic

PorkbunProvider does not support dynamic records.

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
