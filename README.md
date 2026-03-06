# Awesome Embedded Linux Security
A collection of awesome tools, books, resources, software, documents and cool stuff about embedded linux security and linux platform security.

[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

Thanks to all [contributors](https://github.com/kayranfatih/awesome-embedded-linux-security/graphs/contributors). The goal is to build community-driven collection of well-known resources.

## Contents
- [**Root of Trust**](#root-of-trust)
- [**Trusted Execution Environment (TEE)**](#trusted-execution-environment-tee)
- [**Secure Boot**](#secure-boot)
- [**Bootloaders**](#bootloaders)
- [**Over-the-Air Updates**](#over-the-air-updates)
- [**Access Control and Kernel modules**](#access-control-and-kernel-modules)
- [**Operating Systems**](#operating-systems)
- [**Container Security**](#container-security)
  - [Foundations and Guidance](#foundations-and-guidance)
  - [Image Scanning and Supply Chain](#image-scanning-and-supply-chain)
  - [Runtime and Isolation](#runtime-and-isolation)
  - [Benchmarks and Platform Docs](#benchmarks-and-platform-docs)
- [**Useful Websites**](#useful-websites)
- [**Standards and Regulations**](#standards-and-regulations)
- [**Host-based Intrusion Detection Systems**](#host-based-intrusion-detection-systems)
- [**Kernel Memory Protection**](#kernel-memory-protection)
- [**Return Oriented Programming**](#return-oriented-programming)
- [**Data Integrity and Security**](#data-integrity-and-security)
  - [Block Level Encryption](#block-level-encryption)
  - [Filesystem Level Encryption](#filesystem-level-encryption)
  - [Usage and Implementation Details](#usage-and-implementation-details)
  - [Considerations](#considerations)
- [**Hardening Yocto**](#hardening-yocto)
- [**Supply Chain Security and SBOM**](#supply-chain-security-and-sbom)
- [**Firmware Analysis and Reverse Engineering**](#firmware-analysis-and-reverse-engineering)
- [**Linux Firewalls**](#linux-firewalls)
- [**Testing Linux Software for Security**](#testing-linux-software-for-security)
  - [Static Analysis](#static-analysis)
  - [Dynamic Analysis](#dynamic-analysis)
  - [Fuzz Testing](#fuzz-testing)
  - [Linux Kernel Fuzzers](#linux-kernel-fuzzers)
  - [Sanitizers](#sanitizers)
  - [Cyclomatic Complexity](#cyclomatic-complexity)
- [**Lockdown**](#lockdown)
  - [Disabled/Restricted Access](#disabledrestricted-access)
  - [Signed Kernel Modules](#signed-kernel-modules)
  - [IMA Secure Boot Rules](#ima-secure-boot-rules)
- [**Books**](#books)

## Root of Trust
- [OpenTitan](https://opentitan.org/) - Open source silicon root of trust project with secure boot, key management, and lifecycle support.
- [Project Cerberus](https://github.com/Azure/Project-Cerberus) - Hardware root of trust reference implementation focused on platform firmware protection and attestation.
- [Trusted Platform Module (TPM)](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/) - TPM can securely store keys, certificates, and platform measurements for attestation and measured boot.
- [Device Identifier Composition Engine (DICE)](https://trustedcomputinggroup.org/work-groups/dice-architectures/) - Lightweight root of trust architecture for constrained devices and firmware identity.
- [Keylime](https://keylime.dev/) - Remote attestation framework for verifying Linux system integrity at runtime.
- [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) - Command-line tools for TPM 2.0 provisioning, measurement, sealing, and attestation.
- [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) - TPM 2.0 software stack for Linux user space integration.

## Trusted Execution Environment (TEE)
- [ARM TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-a) - Hardware isolation technology used by many Linux-capable Arm SoCs.
- [RISC-V Keystone](https://keystone-enclave.org/) - Open source project for building customizable TEEs on RISC-V.
- [OP-TEE](https://optee.readthedocs.io/en/latest/) - Open source TEE for Arm TrustZone with broad embedded Linux adoption.
- [Intel SGX (Software Guard Extensions)](https://github.com/intel/linux-sgx) - Intel enclave technology for isolating code and data in Linux environments.
- [AMD SEV (Secure Encrypted Virtualization)](https://www.amd.com/en/developer/sev.html) - AMD technology for encrypting virtual machine memory and strengthening guest isolation.
- [Trusted Firmware-A](https://trustedfirmware-a.readthedocs.io/en/latest/) - Reference implementation for Arm secure world boot stages and trusted boot flows.
- [Trusted Firmware-M](https://trustedfirmware-m.readthedocs.io/en/latest/) - Secure processing environment and PSA-aligned reference stack for Cortex-M companions.
- [Hafnium](https://hafnium.readthedocs.io/en/latest/) - Secure Partition Manager and hypervisor relevant to isolation on modern Arm platforms.

## Secure Boot
- [UEFI Secure Boot](https://uefi.org/specifications) - UEFI specifications, including the Secure Boot protocol.
- [Secure Boot on ARM](https://developer.arm.com/documentation/den0077/latest/) - Arm firmware security requirements covering secure boot implementation on Arm-based platforms.
- [Linux Kernel Documentation](https://docs.kernel.org/security/keys/core.html) - Linux kernel documentation on key management and integration with UEFI Secure Boot.
- [Secure Boot with OpenEmbedded/Yocto](https://docs.yoctoproject.org/5.2.2/dev-manual/securing-images.html) - Yocto Project documentation on securing images and integrating secure boot support.
- [Introduction to UEFI Secure Boot](https://www.happyassassin.net/2014/01/25/uefi-boot-how-does-that-actually-work-then/) - In-depth overview of how UEFI Secure Boot works.
- [Implementing Secure Boot in Embedded Linux](https://blog.codecentric.de/en/2019/03/implementing-secure-boot-linux-embedded/) - Practical guide on implementing secure boot in embedded Linux systems.
- [Secure Boot for Embedded Devices](https://www.nxp.com/docs/en/application-note/AN12167.pdf) - NXP application note covering secure boot design choices for embedded devices.
- [Overview of Secure Boot in Linux](https://events.static.linuxfound.org/sites/events/files/slides/Secure%20boot%20with%20linux%20.pdf) - Linux Foundation slides providing a concise secure boot overview.
- [U-Boot Verified Boot](https://docs.u-boot.org/en/latest/usage/fit/verified-boot.html) - FIT signature verification for authenticated boot chains.
- [U-Boot Measured Boot](https://docs.u-boot.org/en/latest/usage/measured_boot.html) - Measured boot support for TPM-backed trust chains.
- [MCUboot](https://docs.mcuboot.com/) - Secure bootloader commonly used with Linux-capable systems that also ship MCU companions.
- [fwupd](https://fwupd.org/) - Linux firmware update ecosystem with signed metadata and device plugin support.
- [Linux Vendor Firmware Service (LVFS)](https://lvfs.readthedocs.io/en/latest/) - Signed firmware distribution service used by the fwupd ecosystem.

## Bootloaders
- [U-Boot](https://docs.u-boot.org/) - Powerful bootloader used primarily in embedded systems, with broad architecture support and current upstream documentation.
- [GNU GRUB (GRand Unified Bootloader)](https://www.gnu.org/software/grub/) - Popular Linux bootloader with strong scripting and multi-boot support.
- [systemd-boot](https://www.freedesktop.org/software/systemd/man/latest/systemd-boot.html) - Simple UEFI boot manager that integrates well with modern Linux systems.
- [coreboot](https://www.coreboot.org/) - Firmware platform often paired with payloads such as GRUB, LinuxBoot, or SeaBIOS.
- [rEFInd](https://www.rodsbooks.com/refind/) - UEFI boot manager with a graphical interface and multi-OS support.
- [Barebox](https://barebox.org/) - Modern embedded bootloader designed as a successor to U-Boot.
- [Petitboot](https://github.com/open-power/petitboot) - Linux-based bootloader environment with network and multiple file system support.
- [RedBoot](http://ecos.sourceware.org/redboot/) - Legacy bootstrap environment for embedded systems based on eCos.

## Over-the-Air Updates
- [RAUC](https://rauc.io/) - Robust A/B update framework with signed bundles for embedded Linux systems.
- [SWUpdate](https://sbabic.github.io/swupdate/) - OTA and local software update framework with image signing and rollback support.
- [Mender](https://docs.mender.io/) - OTA platform with signed artifacts, delta updates, and fleet management.
- [The Update Framework (TUF)](https://theupdateframework.io/) - Security framework for resilient software update metadata and compromise recovery.
- [Uptane](https://uptane.org/) - TUF-derived security framework designed for automotive and fleet update systems.
- [Aktualizr](https://github.com/uptane/aktualizr) - Uptane-compliant OTA client for automotive and embedded Linux deployments.

## Access Control and Kernel modules
- [SELinux (Security-Enhanced Linux)](https://github.com/SELinuxProject/selinux) - Linux security module that provides mandatory access control and mature policy tooling.
- [AppArmor](https://docs.kernel.org/admin-guide/LSM/apparmor.html) - LSM that restricts program capabilities with per-program profiles.
- [Tomoyo](https://tomoyo.sourceforge.net/) - Linux security module focused on usable policy learning and behavioral profiling.
- [Yama](https://docs.kernel.org/admin-guide/LSM/Yama.html) - LSM that adds system-wide hardening features such as ptrace restrictions.
- [Audit](https://github.com/linux-audit/audit-documentation/wiki) - Linux Audit subsystem documentation for collecting and analyzing security-relevant events.
- [Integrity Measurement Architecture (IMA)](https://ima-doc.readthedocs.io/en/latest/ima-concepts.html) - Measures and appraises files to detect tampering and enforce trust decisions.
- [IMA Policy Syntax](https://ima-doc.readthedocs.io/en/latest/policy-syntax.html) - Practical policy reference for deploying IMA measurement and appraisal rules.
- [eBPF (Extended Berkeley Packet Filter)](https://docs.kernel.org/bpf/) - Sandboxed in-kernel programs used for observability, networking, and security controls.
- [LKRG (Linux Kernel Runtime Guard)](https://www.openwall.com/lkrg/) - Runtime kernel integrity monitor for detecting kernel-level tampering.
- [Seccomp (Secure Computing Mode)](https://docs.kernel.org/userspace-api/seccomp_filter.html) - Linux kernel feature for system call filtering and attack surface reduction.
- [SMACK (Simplified Mandatory Access Control Kernel)](https://docs.kernel.org/admin-guide/LSM/Smack.html) - Rule-based LSM used in some embedded and appliance systems.
- [Landlock](https://docs.kernel.org/userspace-api/landlock.html) - Unprivileged application sandboxing for Linux user space.
- [LoadPin](https://docs.kernel.org/admin-guide/LSM/LoadPin.html) - Restricts kernel module and firmware loading to a trusted filesystem.
- [Integrity Policy Enforcement (IPE)](https://docs.kernel.org/admin-guide/LSM/ipe.html) - Newer trust-based execution policy mechanism in the Linux kernel.

## Operating Systems
- [OpenWRT](https://openwrt.org/) - Linux operating system targeting embedded devices, routers, and appliances.
- [Yocto Project](https://www.yoctoproject.org/) - Templates, tools, and methods to create custom Linux-based systems for embedded products.
- [Buildroot](https://buildroot.org/) - Efficient tool to generate embedded Linux systems through cross-compilation.
- [OpenEmbedded](https://www.openembedded.org/) - Build framework with broad package metadata and strong customization.
- [Ubuntu Core](https://ubuntu.com/core) - Minimal Ubuntu variant designed for IoT devices and appliances with transactional updates.
- [PREEMPT-RT](https://wiki.linuxfoundation.org/realtime/start) - Real-time Linux work relevant to deterministic and industrial platforms.
- [Xenomai](https://xenomai.org/) - Real-time development framework for Linux.
- [Alpine Linux](https://www.alpinelinux.org/) - Lightweight distribution known for a small footprint and hardening-oriented defaults.
- [Tiny Core Linux](http://tinycorelinux.net/) - Minimal Linux distribution for very resource-constrained environments.
- [BalenaOS](https://www.balena.io/os/) - Container-centric Linux distribution for IoT and edge deployments.
- [ROCK Pi](https://wiki.radxa.com/RockpiS/downloads) - Linux images and support resources for ROCK Pi single-board computers.
- [Raspberry Pi OS](https://www.raspberrypi.com/software/) - Official operating system for Raspberry Pi devices.

## Container Security

### Foundations and Guidance
- [Container Security: A Comprehensive Overview](https://www.redhat.com/en/topics/containers/what-is-container-security) - Overview of container security challenges and best practices.
- [Top 10 Container Security Risks](https://www.cisecurity.org/blog/top-10-container-security-risks/) - Summary of common security risks associated with container deployments.
- [Securing Containerized Applications](https://blog.aquasec.com/kubernetes-security-best-practices) - Best practices for securing containerized applications in Kubernetes environments.
- [Introduction to Docker Security](https://www.docker.com/blog/docker-security-best-practices/) - Docker's guide to security best practices for build and deployment.
- [Docker Security Documentation](https://docs.docker.com/engine/security/) - Official Docker security documentation.
- [Kubernetes Security Guide](https://kubernetes.io/docs/concepts/security/) - Official Kubernetes security concepts and hardening guidance.

### Image Scanning and Supply Chain
- [Clair](https://github.com/quay/clair) - Vulnerability scanner for container images.
- [Trivy](https://trivy.dev/latest/) - Scanner for container images, OS packages, IaC, secrets, and SBOM workflows.
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner for container images and SBOM inputs.
- [Syft](https://github.com/anchore/syft) - SBOM generator for container images and file systems.

### Runtime and Isolation
- [Docker Bench Security](https://github.com/docker/docker-bench-security) - Checks dozens of Docker deployment best practices.
- [Falco](https://falco.org/) - Runtime security project that monitors abnormal behavior in container workloads.
- [Cilium](https://cilium.io/) - eBPF-based networking, visibility, and security for containers and Kubernetes.
- [LXD](https://linuxcontainers.org/lxd/) - System container manager for Linux with a stronger VM-like isolation model than application containers.
- [Docker Rootless Mode](https://docs.docker.com/engine/security/rootless/) - Runs the Docker daemon and containers without root privileges.

### Benchmarks and Platform Docs
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/) - Comprehensive guide to securing Docker containers.
- [NSA/CISA Kubernetes Hardening Guidance](https://www.nsa.gov/Press-Room/Digital-Media-Center/Document-Gallery/igphoto/2003066362/) - Practical hardening guidance for securing Kubernetes clusters and workloads.
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) - Concise hardening guidance for Docker deployments.
- [Docker Security Cheat Sheet](https://www.linux.com/topic/security/docker-security-cheat-sheet/) - Summary of Docker security mitigations and operational practices.
- [Container Security with AWS](https://aws.amazon.com/containers/security/) - AWS guidance for securing ECS and EKS environments.
- [Google Kubernetes Engine (GKE) Security](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster) - GKE cluster hardening guidance.
- [Sigstore](https://sigstore.dev/) - Artifact signing and verification ecosystem increasingly used in container and Kubernetes pipelines.

## Useful Websites
- [Trusted Computing Group (TCG)](https://trustedcomputinggroup.org/) - Open standards and specifications around TPM, DICE, and trusted computing.
- [OpenSSF](https://openssf.org/) - Security guidance and tooling around open source software supply chains.
- [OWASP Internet of Things Project](https://owasp.org/www-project-internet-of-things/) - Security references relevant to connected and embedded devices.
- [Linux Kernel Security Documentation](https://docs.kernel.org/security/index.html) - Primary source for current kernel security mechanisms and hardening features.
- [Yocto Project Security Advisories](https://www.yoctoproject.org/security/) - Security notices and updates relevant to Yocto-based products.
- [PSA Certified](https://www.psacertified.org/) - Security framework and certification program for connected devices and platforms.
- [NIST NVD](https://nvd.nist.gov/) - U.S. National Vulnerability Database for tracking CVEs.
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) - Prioritization signal for actively exploited issues.

## Standards and Regulations
- [ETSI EN 303 645](https://www.etsi.org/newsroom/press-releases/1789-2020-06-etsi-releases-world-leading-consumer-i) - Baseline consumer IoT cybersecurity standard for internet-connected consumer products.
- [NISTIR 8259A: IoT Device Cybersecurity Capability Core Baseline](https://www.nist.gov/publications/iot-device-cybersecurity-capability-core-baseline) - Technical capability baseline for IoT device security requirements.
- [NIST SP 800-193: Platform Firmware Resiliency Guidelines](https://www.nist.gov/publications/platform-firmware-resiliency-guidelines) - Guidance on protecting, detecting, and recovering platform firmware.
- [NIST SSDF (SP 800-218)](https://csrc.nist.gov/projects/ssdf) - Secure software development framework for reducing software vulnerability risk across the lifecycle.
- [FIPS 140-3 / CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program) - U.S. cryptographic module validation program used widely in regulated environments.
- [Common Criteria / CCRA](https://www.commoncriteriaportal.org/index.cfm) - International framework for security evaluation and mutual recognition of certified IT products.
- [EUCC](https://certification.enisa.europa.eu/certification-library_en) - EU Common Criteria-based cybersecurity certification scheme for hardware, software, and components.
- [Cyber Resilience Act (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/2024-11-20/eng) - EU regulation on horizontal cybersecurity requirements for products with digital elements.
- [RED Delegated Regulation (EU) 2022/30](https://eur-lex.europa.eu/eli/reg_del/2022/30/2023-10-27/eng) - EU cybersecurity, privacy, and fraud-protection requirements for categories of internet-connected radio equipment.
- [ISA/IEC 62443](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards) - Widely used OT and industrial control system cybersecurity standards relevant to industrial Linux devices.

## Host-based Intrusion Detection Systems
- [OSSEC](https://www.ossec.net/) - Open source host-based intrusion detection system with log analysis and file integrity monitoring.
- [Wazuh](https://wazuh.com/) - OSSEC-derived platform with additional monitoring and response features.
- [Tripwire](https://www.tripwire.com/) - Commercial HIDS with file integrity monitoring and policy-based alerting.
- [Samhain](https://la-samhna.de/samhain/) - Open source HIDS with file integrity checking, monitoring, and rootkit detection.
- [chkrootkit](http://www.chkrootkit.org/) - Tool to locally check for signs of a rootkit.
- [AIDE](https://aide.github.io/) - Advanced Intrusion Detection Environment, a file and directory integrity checker.
- [afick](http://afick.sourceforge.net/) - Another file integrity checker for monitoring filesystem changes.
- [Open Source Tripwire](https://github.com/Tripwire/tripwire-open-source) - Open source file integrity monitoring tool.
- [rkhunter](https://rkhunter.sourceforge.net/) - Rootkit, backdoor, and local exploit scanner.

## Kernel Memory Protection
- [AddressSanitizer (ASan)](https://clang.llvm.org/docs/AddressSanitizer.html) - Runtime memory error detector for C and C++.
- [KASAN (Kernel Address Sanitizer)](https://docs.kernel.org/dev-tools/kasan.html) - Dynamic memory error detector tailored for kernel code.
- [KFENCE](https://docs.kernel.org/dev-tools/kfence.html) - Low-overhead memory safety bug detector for long-running tests.
- [UBSAN](https://docs.kernel.org/dev-tools/ubsan.html) - Undefined behavior detection support for kernel builds.
- [FORTIFY_SOURCE](https://docs.kernel.org/dev-tools/fortify.html) - Compile-time and runtime hardening for common memory operations.
- [Strict Kernel Memory Permissions](https://docs.kernel.org/security/self-protection.html#strict-kernel-memory-permissions) - Prevents writable executable mappings in kernel and module memory.
  - Config options: `CONFIG_STRICT_KERNEL_RWX`, `CONFIG_STRICT_MODULE_RWX`, `CONFIG_DEBUG_ALIGN_RODATA`
- [Kernel Address Space Layout Randomization (KASLR)](https://docs.kernel.org/security/self-protection.html#kernel-address-space-layout-randomization-kaslr) - Randomizes the kernel virtual address base to mitigate memory-based attacks.
  - Config option: `CONFIG_RANDOMIZE_BASE`
- [Stack Canary](https://docs.kernel.org/security/self-protection.html#canaries-blinding-and-other-secrets) - Inserts a canary before return addresses to detect stack smashing.
  - Config option: `CONFIG_STACK_PROTECTOR`
- [Control-Flow Integrity (CFI)](https://docs.kernel.org/dev-tools/llvm.html) - Clang-backed forward-edge control flow protection for supported kernel builds.
- [SLUB Allocator Heap Memory Security](https://events.static.linuxfound.org/sites/events/files/slides/slaballocators.pdf) - Notes on why SLUB is generally preferred over older slab allocators from a security perspective.
- [Kernel Self-Protection Project (KSPP)](https://kspp.github.io/) - Community effort tracking hardening work across the Linux kernel.

## Return Oriented Programming
Return-Oriented Programming (ROP) is an exploitation technique that chains together short code fragments called gadgets from existing program code. It is relevant both for offensive research and for understanding why modern mitigations matter.

- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - Command-line tool for finding gadgets and building ROP chains.
- [ROPInjector](https://github.com/NytroRST/ROPInjector) - Tool for generating and injecting ROP payloads.
- [ROPShell](https://github.com/alpha1ab/ROPShell) - Python script for helping build ROP-based exploits.
- [RP++](https://github.com/0vercl0k/rp) - ROP gadget discovery tool for binaries.
- [Ropper](https://github.com/sashs/ropper) - Gadget finder supporting x86, x86_64, ARM, ARM64, MIPS, PowerPC, and SPARC64.
- [Pwntools](https://github.com/Gallopsled/pwntools) - Exploit development library and framework widely used in binary research.

## Data Integrity and Security
### Block Level Encryption
- [dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html) - Linux kernel feature providing transparent integrity checking of block devices.
- [fs-verity](https://docs.kernel.org/filesystems/fsverity.html) - File-level authenticity checking for read-only files.
- [dm-crypt](https://gitlab.com/cryptsetup/cryptsetup/) - Block-level disk encryption mechanism in the Linux kernel.
  - Config Option: `CONFIG_DM_CRYPT`
- [Inline Encryption](https://docs.kernel.org/block/inline-encryption.html) - Hardware-assisted inline storage encryption support.
  - Config Option: `CONFIG_BLK_INLINE_ENCRYPTION`

### Filesystem Level Encryption
- [fscrypt](https://docs.kernel.org/filesystems/fscrypt.html) - Filesystem-level encryption supporting ext4, F2FS, and UBIFS.
  - Config Options: `CONFIG_ECRYPT_FS`, `CONFIG_FS_ENCRYPTION`
  - User-space tools: [fscryptctl](https://github.com/google/fscryptctl)

### Usage and Implementation Details
- [fscrypt Documentation](https://docs.kernel.org/filesystems/fscrypt.html) - Official documentation for deploying fscrypt.
- [Cryptsetup Repository](https://gitlab.com/cryptsetup/cryptsetup/) - User-space tooling for configuring dm-crypt.
- [Android Security: File-Based Encryption](https://source.android.com/security/encryption/file-based) - Android usage of fscrypt for directory-level encryption.
- [Chrome OS Security: Encrypted User Data](https://chromium.googlesource.com/chromiumos/docs/+/master/security/encrypted_user_data.md) - Overview of Chrome OS encrypted user data.

### Considerations
- **Integrity Protection**: dm-verity and fs-verity provide integrity checking, while dm-crypt and fscrypt focus on confidentiality.
- **Metadata Encryption**: dm-crypt protects all block device metadata, while fscrypt primarily protects file contents and filenames.

## Hardening Yocto
- [Yocto CVE Check Documentation](https://docs.yoctoproject.org/dev-manual/vulnerabilities.html) - Current Yocto documentation for vulnerability scanning and CVE workflows.
- [Yocto Project Security Advisories](https://www.yoctoproject.org/security/) - Official security advisories and updates for the Yocto Project.
- [Yocto SBOM Generation](https://docs.yoctoproject.org/dev-manual/sbom.html) - Yocto documentation for SPDX-based software bill of materials generation.
- [Securing Images in the Yocto Project](https://docs.yoctoproject.org/5.2.2/dev-manual/securing-images.html) - Current guidance on hardening images, security flags, and secure boot considerations.
- [meta-security](https://github.com/openembedded/meta-security) - OpenEmbedded layer containing useful security packages and metadata for Yocto-based systems.

## Supply Chain Security and SBOM
- [SPDX](https://spdx.dev/) - Standard for software bill of materials and license metadata exchange.
- [CycloneDX](https://cyclonedx.org/) - SBOM format focused on security and dependency tracking.
- [Reproducible Builds](https://reproducible-builds.org/docs/definition/) - Practices for making build outputs independently verifiable.
- [Syft](https://github.com/anchore/syft) - SBOM generator for file systems, container images, and packages.
- [Grype](https://github.com/anchore/grype) - Vulnerability scanner for SBOMs and package inventories.
- [OSV-Scanner](https://github.com/google/osv-scanner) - Scanner backed by the Open Source Vulnerabilities database.
- [in-toto](https://in-toto.io/) - Framework for supply chain provenance and tamper detection in software pipelines.
- [SLSA](https://slsa.dev/) - Framework for measuring and improving software supply chain integrity.
- [OpenVEX](https://openvex.dev/) - Machine-readable format for expressing whether known vulnerabilities affect shipped products.
- [diffoscope](https://diffoscope.org/) - Deep artifact comparison tool useful for reproducible builds and firmware diffing.

## Firmware Analysis and Reverse Engineering
- [binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware image extraction and signature analysis tool.
- [FACT](https://github.com/fkie-cad/FACT_core) - Firmware Analysis and Comparison Tool for large-scale unpacking and triage.
- [EMBA](https://github.com/e-m-b-a/emba) - Firmware security analyzer covering extraction, SBOM, static checks, and emulation-assisted analysis.
- [FirmAE](https://github.com/pr0v3rbs/FirmAE) - Emulation framework for dynamic analysis of Linux-based firmware images.
- [Firmadyne](https://github.com/firmadyne/firmadyne) - Research platform for emulating and analyzing Linux firmware.
- [Ghidra](https://ghidra-sre.org/) - Reverse engineering suite for bootloaders, kernels, and firmware blobs.
- [radare2](https://rada.re/n/) - Reverse engineering framework for binary and firmware analysis.
- [QEMU](https://www.qemu.org/) - Hardware emulation platform useful for secure boot testing and firmware analysis.

## Linux Firewalls
- [IPtables](https://netfilter.org/documentation/index.html) - Kernel-level firewall utility for filtering and manipulating network packets.
- [NFTables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) - Successor to iptables with a cleaner syntax and better flexibility.
- [Firewalld](https://firewalld.org/documentation/) - Dynamic firewall management layer used in several Linux distributions.
- [UFW (Uncomplicated Firewall)](https://help.ubuntu.com/community/UFW) - Simpler command-line front-end for iptables/nftables based workflows.

## Testing Linux Software for Security
Testing Linux software for security vulnerabilities is crucial to ensure reliability and system integrity. These tools are useful for user space, kernel, embedded products, and Linux-based platforms.

### Static Analysis
Static analysis examines source code or binaries without executing them. It helps identify security vulnerabilities, coding errors, and compliance issues early.
  - [Cppcheck](https://cppcheck.sourceforge.io/) - Static analysis tool for C and C++ code.
  - [Clang Static Analyzer](https://clang.llvm.org/docs/ClangStaticAnalyzer.html) - Static analysis tool based on Clang for C and C++ code.
  - [FindBugs](http://findbugs.sourceforge.net/) - Static analysis tool for Java code.
  - [Brakeman](https://brakemanscanner.org/) - Static analysis tool for Ruby on Rails applications.
  - [Coverity](https://scan.coverity.com/) - Commercial static analysis platform for identifying defects and security vulnerabilities.
  - [Klocwork](https://www.perforce.com/manuals/klocwork) - Static analysis tool for finding defects and security weaknesses in large codebases.
  - [SonarQube](https://www.sonarqube.org/) - Platform for continuous inspection of code quality and security.

### Dynamic Analysis
Dynamic analysis executes software with different inputs and observes runtime behavior to identify vulnerabilities.
  - [Valgrind](https://valgrind.org/) - Dynamic analysis tool for memory debugging, leak detection, and profiling.
  - [GDB](https://www.gnu.org/software/gdb/) - GNU Debugger for stepping through code and inspecting memory.
  - [Strace](https://strace.io/) - System call tracer that captures system calls made by a program.

### Fuzz Testing
Fuzz testing feeds invalid, unexpected, or random input into software to uncover crashes and security bugs.
  - [American Fuzzy Lop (AFL)](https://lcamtuf.coredump.cx/afl/) - Classic fuzz-testing tool for finding security vulnerabilities.
  - [AFL++](https://github.com/AFLplusplus/AFLplusplus) - Improved AFL with broader features and better modern workflows.
  - [libFuzzer](https://llvm.org/docs/LibFuzzer.html) - In-process fuzzer for parser-heavy C and C++ code.
  - [honggfuzz](https://github.com/google/honggfuzz) - Coverage-aware fuzzer with sanitizer-friendly workflows.
  - [Peach Fuzzer](https://peachtech.gitlab.io/peach-fuzzer-community/) - Platform for fuzzing applications, protocols, and file formats.

### Linux Kernel Fuzzers
  - [Trinity](https://github.com/kernelslacker/trinity) - Syscall fuzzer specifically designed for the Linux kernel.
  - [syzkaller](https://github.com/google/syzkaller) - State of the art Linux kernel fuzzer developed by Google.
  - [KUnit](https://docs.kernel.org/dev-tools/kunit/) - Upstream Linux kernel unit testing framework.
  - [KernelCI](https://kernelci.org/) - Continuous integration infrastructure for validating kernel changes on real hardware.

### Sanitizers
Sanitizers are runtime tools that detect memory errors, data races, and undefined behavior.
  - [AddressSanitizer (ASan)](https://clang.llvm.org/docs/AddressSanitizer.html) - Detects memory corruption bugs such as buffer overflows and use-after-free errors.
  - [ThreadSanitizer (TSan)](https://clang.llvm.org/docs/ThreadSanitizer.html) - Detects data races and synchronization issues.
  - [UndefinedBehaviorSanitizer (UBSan)](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) - Detects undefined behavior in C and C++ programs.

### Cyclomatic Complexity
Cyclomatic Complexity (CC) estimates the number of linearly independent paths through a program and helps identify hard-to-test code.
  - [Lizard](https://github.com/terryyin/lizard) - Command-line tool for Cyclomatic Complexity and maintainability metrics.

## Lockdown
Lockdown is a Linux kernel security feature designed to prevent unauthorized access to a running kernel image and protect kernel integrity.

### Disabled/Restricted Access
Lockdown disables or restricts access to several critical kernel interfaces and resources, including:
  - `/dev/mem`, `/dev/kmem`, `/dev/kcore`, and `/dev/ioports`
  - BPF and kprobes in restricted configurations
  - `debugfs` access that can undermine kernel trust assumptions

### Signed Kernel Modules
  - Lockdown can require that kernel modules be signed or appraised by the Integrity Measurement Architecture (IMA) before loading.

### IMA Secure Boot Rules
  - Lockdown may enforce `secure_boot` rules in IMA policy so that only trusted code is executed during boot.

## Books
- [Mastering Linux Security and Hardening](https://www.packtpub.com/product/mastering-linux-security-and-hardening-third-edition/9781837630516) - Linux hardening reference with practical coverage of kernel, services, and operational controls.
- [Practical Linux Security Cookbook](https://www.amazon.de/Practical-Linux-Security-Cookbook-environment/dp/1789138396) - Practical recipes for securing Linux systems and services.
- [Embedded Linux Systems with the Yocto Project](https://www.pearson.com/en-us/subject-catalog/p/embedded-linux-systems-with-the-yocto-project/P200000003188/9780133443240) - Good background for building maintainable embedded Linux systems that can then be hardened correctly.
- [Practical Binary Analysis](https://nostarch.com/binaryanalysis) - Strong reverse engineering and firmware analysis foundation for offensive and defensive work.
- [The Firmware Handbook](https://www.oreilly.com/library/view/the-firmware-handbook/9781098178864/) - Modern firmware engineering reference with security-relevant design and maintenance topics.
