# SIFT Workstation

SANS collection of free and open-source incident response and forensic tools on Ubuntu.

## When I Use It

* A ready-made Linux analysis environment with Volatility, The Sleuth Kit, log2timeline/Plaso, and many other tools already installed
* Training and practice, since many SANS and community exercises assume it

## Installation

* Download the prebuilt virtual machine from <https://www.sans.org/tools/sift-workstation/>
* Or install on an existing Ubuntu system with the Cast installer: <https://github.com/ekristen/cast>

## Common Tasks

| Task | Tools on SIFT |
| :--- | :--- |
| Memory analysis | Volatility |
| File system and disk image analysis | The Sleuth Kit (`fls`, `icat`, `mmls`) |
| Super timelines | log2timeline / Plaso |
| Mounting images read-only | `ewfmount`, `mount -o ro,loop` |
| Carving | Scalpel, Foremost, bulk_extractor |

## Reading the Output

Each tool has its own output; see the tool pages in this section. Keep evidence on a separate, read-only mounted volume rather than copying it into the VM's home directory.

## Related

* [Forensic Workstation](../forensic-workstation.md)
* [Volatility](volatility.md)

## Resources

* [SANS SIFT Workstation](https://www.sans.org/tools/sift-workstation/)
* [SIFT Workstation GitHub](https://github.com/teamdfir/sift-saltstack)
