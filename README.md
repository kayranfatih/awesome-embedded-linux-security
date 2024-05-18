# Awesome Embedded Linux Security
A collection of awesome tools, books, resources, software, documents and cool stuff about embedded linux security
[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

Thanks to all [contributors](https://github.com/kayranfatih/awesome-embedded-linux-security/graphs/contributors). The goal is to build community-driven collection of  well-known resources.

## Contents
- [**Root of Trust**](#Root-of-Trust)
- [**Trusted Execution Environment (TEE)**](#Trusted-Execution-Environment-TEE)
- [**Secure Boot**](#Secure-Boot)
- [**Bootloaders**](#Bootloaders)
- [**Access Control and Kernel modules**](#Access-Control-and-Kernel-modules)
- [**Operating Systems**](#Operating-Systems)
- [**Container Security**](#Container-Security)
  - [Articles](#Articles)
  - [Tools](#Tools)
  - [Best Practices](#Best-Practices)
  - [Guides and Documentation](#Guides-and-Documentation)
- [**Useful Websites**](#Useful-Websites)
- [**Host-based Intrusion Detection Systems**](#Host-based-Intrusion-Detection-Systems)
- [**Kernel Memory Protection**](#kernel-memory-protection)
- [**Return Oriented Programming**](#return-oriented-programming)
- [**Data Integrity and Security**](#data-integrity-and-security)
  - [Block Level Encryption](#block-level-encryption)
  - [Filesystem Level Encryption](#filesystem-level-encryption)
  - [Usage and Implementation Details](#usage-and-implementation-details)
  - [Considerations](#considerations)
- [**Hardening Yocto**](#hardening-yocto)
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

## Root of Trust
- [OpenTitan](https://opentitan.org/) - OpenTitan is the first open source project building a transparent, high-quality reference design and integration guidelines for silicon root of trust (RoT) chips
- [Project Cerberus](https://github.com/Azure/Project-Cerberus) - Project Cerberus is designed to be a hardware root of trust (RoT) for server platforms. It provides functionality to enforce secure boot for firmware on devices with or without intrinsic secure boot capabilities. It also provides a mechanism to securely attest to the state of the device firmware.
- [Trusted Platform Module (TPM)](https://trustedcomputinggroup.org/resource/trusted-platform-module-tpm-summary/) - TPM (Trusted Platform Module) is a computer chip (microcontroller) that can securely store artifacts used to authenticate the platform (your PC or laptop). These artifacts can include passwords, certificates, or encryption keys. A TPM can also be used to store platform measurements that help ensure that the platform remains trustworthy.
- [Device Identifier Composition Engine (DICE)](https://trustedcomputinggroup.org/what-is-a-device-identifier-composition-engine-dice/) - DICE is a hardware Root-of-Trust (RoT) used to protect the devices and components where a TPM would be impractical or infeasible. When a TPM is present, DICE is used to protect communication with the TPM and provides the Root of Trust for Measurement (RTM) for the platform. DICE was designed to close critical gaps in infrastructure and help to establish safeguarding measures for devices. The DICE RoT can also be easily integrated into existing infrastructure, with the architecture being flexible and interoperable with existing security standards.
  
## Trusted Execution Environment (TEE)
- [ARM TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-m) - TrustZone technology for Arm Cortex-M processors enables robust levels of protection at all cost points for IoT devices. The technology reduces the potential for attack by isolating the critical security firmware, assets and private information from the rest of the application.
- [RISC-V Keystone](https://keystone-enclave.org/) - Keystone is an open-source project for building customizable trusted execution environments (TEEs) based on RISC-V for various platforms and use cases. 
- [OP-TEE](https://www.trustedfirmware.org/projects/op-tee/) - OP-TEE is an open-source TEE designed for ARM TrustZone. It provides a secure and efficient environment for running trusted applications on ARM processors, implementing the GlobalPlatform TEE system architecture and APIs.
- [Intel SGX (Software Guard Extensions)](https://github.com/intel/linux-sgx) - Intel SGX is a set of security-related instruction codes that are built into modern Intel CPUs. It allows applications to create secure enclaves for code and data. While SGX itself is not open-source, there are open-source SDKs and tools for developing SGX applications.
- [AMD SEV (Secure Encrypted Virtualization](https://github.com/AMDESE/AMDSEV) -  AMD SEV is a technology that provides encryption for virtual machine memory. It helps protect VMs from attacks and unauthorized access. While SEV is a hardware feature, there are open-source tools and frameworks for leveraging SEV in virtualized environments.

## Secure Boot
- [UEFI Secure Boot](https://uefi.org/specifications) - UEFI specifications, including the Secure Boot protocol.
- [Secure Boot on ARM](https://static.docs.arm.com/101028/0301/arm_firmware_security_requirements_whitepaper.pdf) - ARM Firmware Security Requirements whitepaper covering Secure Boot implementation on ARM-based platforms.
- [Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/security/keys/core.html) - Linux kernel documentation on key management and integration with UEFI Secure Boot.
- [Secure Boot with OpenEmbedded/Yocto](https://www.yoctoproject.org/docs/latest/dev-manual/dev-manual.html#secure-boot) - Yocto Project documentation on enabling Secure Boot support in embedded Linux builds.
- [Introduction to UEFI Secure Boot](https://www.happyassassin.net/2014/01/25/uefi-boot-how-does-that-actually-work-then/) - An in-depth overview of UEFI Secure Boot and how it works.
- [Implementing Secure Boot in Embedded Linux](https://blog.codecentric.de/en/2019/03/implementing-secure-boot-linux-embedded/) - A guide on implementing Secure Boot in Embedded Linux systems.
- [Secure Boot for Embedded Devices](https://www.nxp.com/docs/en/application-note/AN12167.pdf) - Application note from NXP providing insights into implementing Secure Boot for embedded devices.
- [Overview of Secure Boot in Linux](https://events.static.linuxfound.org/sites/events/files/slides/Secure%20boot%20with%20linux%20.pdf) - Presentation slides providing an overview of Secure Boot with Linux.

## Bootloaders
- [U-Boot (Das U-Boot)](https://www.denx.de/wiki/U-Boot/) - U-Boot is a powerful bootloader used primarily in embedded systems. It supports a wide range of architectures and file systems, and is highly customizable for different hardware platforms.
- [GNU GRUB GRand Unified Bootloader](https://www.gnu.org/software/grub/) - GRUB is the most popular bootloader for Linux. It supports a wide range of operating systems and file systems, and provides powerful features such as the ability to boot from network and scriptable menu entries.
- [systemd-boot](https://www.freedesktop.org/wiki/Software/systemd/systemd-boot/) - systemd-boot (formerly known as gummiboot) is a simple UEFI boot manager that reads boot entries directly from the EFI system partition. It integrates seamlessly with systemd, making it a good choice for modern Linux systems.
- [coreboot](https://www.coreboot.org/) - coreboot is an extended firmware platform that provides a fast and secure boot experience. It is often used in combination with other bootloaders like GRUB or SeaBIOS.
- [rEFInd](https://www.rodsbooks.com/refind/) - rEFInd is an easy-to-use boot manager for UEFI systems. It provides a graphical interface and supports booting multiple operating systems, including Linux, macOS, and Windows.
- [Barebox](https://barebox.org/) - Barebox is a modern bootloader for embedded systems, designed as a successor to U-Boot. It provides a robust environment with a scripting language, fast boot times, and extensive support for different hardware.
- [Petitboot](https://github.com/open-power/petitboot) - Petitboot is a Linux-based bootloader for the Power architecture, which can also be used on other architectures. It provides a flexible and powerful boot environment with support for multiple file systems and network booting.
- [RedBoot](http://ecos.sourceware.org/redboot/) - RedBoot is a complete bootstrap environment for embedded systems. Based on the eCos Hardware Abstraction Layer, RedBoot inherits the eCos qualities of reliability, compactness, configurability, and portability.

## Access Control and Kernel modules
- [SELinux (Security-Enhanced Linux)](https://selinuxproject.org/page/Main_Page) - Linux kernel security module that provides a mechanism for supporting access control security policies, including mandatory access control (MAC). It helps to confine user programs and system services to the minimum amount of privilege they require to do their jobs.
- [AppArmor](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/apparmor.html) - Linux Security Module that provides MAC style security extension for the Linux kernel. It allows the system administrator to restrict programs' capabilities with per-program profiles.
- [Tomoyo](https://tomoyo.osdn.jp/) - Linux security module that implements mandatory access control policies. It focuses on ease of use and learning mode, which helps to create security policies automatically based on the behavior of the system.
- [Yama](https://www.kernel.org/doc/html/latest/security/Yama.html) - Linux security module that collects system-wide security enhancements that are not handled by other LSMs. It includes restrictions on the ptrace system call, which is used for debugging and manipulating processes.
- [Audit](https://people.redhat.com/sgrubb/audit/) - Linux Audit subsystem provides a way to track security-relevant information on a system. It consists of a kernel component and a user-space component, allowing administrators to create, store, and analyze audit records for security monitoring and compliance.
- [Integrity Measurement Architecture (IMA)](https://sourceforge.net/p/linux-ima/wiki/Home/) - Linux kernel feature that helps ensure the integrity of the system by measuring and attesting to the integrity of files. It can be used to detect if files have been tampered with or altered.
- [eBPF (Extended Berkeley Packet Filter)](https://www.kernel.org/doc/html/latest/bpf/) - Powerful technology that can run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules. It is used for various security purposes, such as monitoring, networking, and performance analysis.
- [LKRG (Linux Kernel Runtime Guard)](https://www.openwall.com/lkrg/) - Kernel module designed to detect and respond to unauthorized modifications to the Linux kernel at runtime. It helps in detecting rootkits and other kernel-level malware.
- [Seccomp (Secure Computing Mode)](https://www.kernel.org/doc/html/latest/userspace-api/seccomp.html) - Linux kernel feature that allows a process to make a one-way transition into a restricted state where it can only make a specified set of system calls. This reduces the kernel attack surface.
- [SMACK (Simplified Mandatory Access Control Kernel)](https://www.kernel.org/doc/html/latest/security/Smack.html) - Linux security module that provides simplified mandatory access control. It implements a rule-based access control mechanism to protect processes and objects on the system.

## Operating Systems
- [OpenWRT](https://openwrt.org/) - The OpenWrt Project is a Linux operating system targeting embedded devices. Instead of trying to create a single, static firmware, OpenWrt provides a fully writable filesystem with package management.
- [Yocto Project](https://www.yoctoproject.org/) - A project that provides templates, tools, and methods to create custom Linux-based systems for embedded products, regardless of hardware architecture.
- [Buildroot](https://buildroot.org/) - A simple, efficient, and easy-to-use tool to generate embedded Linux systems through cross-compilation.
- [OpenEmbedded](https://www.openembedded.org/) - A build framework for embedded Linux systems. It offers a wide range of pre-built packages and customizable configurations.
- [Ubuntu Core](https://ubuntu.com/core) - A minimalist version of Ubuntu designed for IoT devices and appliances. It includes transactional updates and a secure app store.
- [PREEMPT-RT](https://wiki.linuxfoundation.org/realtime/start) - A patchset for the Linux kernel that provides real-time capabilities, suitable for embedded systems requiring deterministic response times.
- [Xenomai](https://xenomai.org/) - A real-time development framework for Linux. It allows developers to create real-time applications alongside Linux user-space applications.
- [Alpine Linux](https://alpinelinux.org/) - A lightweight Linux distribution known for its security features, small footprint, and simplicity. It's suitable for resource-constrained embedded systems.
- [Tiny Core Linux](http://tinycorelinux.net/) - A minimalist Linux distribution designed to be as small as possible while still being a functional operating system. It's suitable for embedded devices with limited storage and memory.
- [BalenaOS](https://www.balena.io/os/) - A container-centric Linux distribution designed for IoT and edge computing. It includes built-in support for containerized applications and fleet management features.
- [ROCK Pi](https://wiki.radxa.com/RockpiS/downloads) - A Linux distribution optimized for ROCK Pi single-board computers, offering pre-built images and software support tailored for these devices.
- [Raspberry Pi OS](https://www.raspberrypi.org/software/) - The official operating system for Raspberry Pi devices, offering a Debian-based Linux distribution with optimized performance and hardware support.

## Container Security

### Articles
- [Container Security: A Comprehensive Overview](https://www.redhat.com/en/topics/containers/what-is-container-security) - An overview of container security challenges and best practices.
- [Top 10 Container Security Risks](https://www.cisecurity.org/blog/top-10-container-security-risks/) - A list of the top 10 security risks associated with container deployments.
- [Securing Containerized Applications](https://blog.aquasec.com/kubernetes-security-best-practices) - Best practices for securing containerized applications running in Kubernetes environments.
- [Introduction to Docker Security](https://www.docker.com/blog/docker-security-best-practices/) - Docker's guide to security best practices for building and deploying containerized applications.

### Tools
- [Docker Bench Security](https://github.com/docker/docker-bench-security) - A script that checks for dozens of common best-practices around deploying Docker containers in production.
- [Clair](https://github.com/quay/clair) - An open-source vulnerability scanner for containers, providing static analysis of container images.
- [Falco](https://falco.org/) - An open-source cloud-native runtime security project that monitors container workloads for abnormal behavior.
- [Cilium](https://cilium.io/) - A network security project that provides network and application layer visibility and security for containers.
- [LXD](https://linuxcontainers.org/lxd/) - A next-generation system container manager providing a more user-friendly and feature-rich interface for managing containers.

### Best Practices
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker/) - A comprehensive guide to securing Docker containers, developed by the Center for Internet Security (CIS).
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/) - Official Kubernetes documentation on security best practices for securing Kubernetes clusters and workloads.
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html) - A cheat sheet from OWASP providing guidance on securing Docker containers.
- [Docker Security Cheat Sheet](https://www.linux.com/topic/security/docker-security-cheat-sheet/) - A concise summary of Docker security best practices and mitigation strategies.

### Guides and Documentation
- [Docker Security Documentation](https://docs.docker.com/engine/security/) - Official Docker documentation covering security features, best practices, and configuration options.
- [Kubernetes Security Guide](https://kubernetes.io/docs/concepts/security/) - Official Kubernetes documentation providing guidance on securing Kubernetes clusters and workloads.
- [Container Security with AWS](https://aws.amazon.com/containers/security/) - AWS documentation on securing containerized applications on Amazon ECS and EKS.
- [Google Kubernetes Engine (GKE) Security](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster) - Google Cloud documentation on hardening your Google Kubernetes Engine (GKE) clusters.

## Useful Websites
- [Trusted Computing Group (TCG)](https://trustedcomputinggroup.org/) - Through open standards and specifications, Trusted Computing Group (TCG) enables secure computing. Benefits of TCG technologies include protection of business-critical data and systems, secure authentication and strong protection of user identities, and the establishment of strong machine identity and network integrity. Trusted hardware and applications reduce enterprise total cost of ownership and support regulatory compliance.

## Host-based Intrusion Detection Systems
- [OSSEC](https://www.ossec.net/) - An open-source host-based intrusion detection system that performs log analysis, file integrity checking, rootkit detection, and real-time alerting.
- [Wazuh](https://wazuh.com/) - A fork of OSSEC with additional features and enhancements, providing security monitoring, incident response, and compliance capabilities.
- [Tripwire](https://www.tripwire.com/) - A commercial HIDS solution that performs file integrity monitoring, change detection, and policy-based alerting for embedded Linux systems.
- [Samhain](http://www.la-samhna.de/samhain/) - An open-source HIDS that provides file integrity checking, system monitoring, and rootkit detection for embedded Linux environments.
- [chrootkit](http://www.chkrootkit.org/) - chkrootkit is a tool to locally check for signs of a rootkit.
- [AIDE](https://aide.github.io/) - Advanced Intrusion Detection Environment, a file and directory integrity checker.
- [afick](http://afick.sourceforge.net/) - Another File Integrity Checker, monitors changes on the file system and detects intrusions.
- [Open Source Tripwire](https://github.com/Tripwire/tripwire-open-source) - Security and data integrity tool for monitoring and alerting on file & directory changes.
- [rkhunter](http://rkhunter.sourceforge.net/) - A rootkit hunter.
- [SAMHAIN](https://la-samhna.de/samhain/) - Provides file integrity checking and log file monitoring/analysis, as well as rootkit detection, port monitoring, detection of rogue SUID executables, and hidden processes. 

## Kernel Memory Protection
- [AddressSanitizer (ASan)](https://github.com/google/sanitizers/wiki/AddressSanitizer) - A runtime memory error detector that finds buffer overflow and use-after-free bugs in C/C++ programs.
- [KASAN (Kernel Address Sanitizer)](https://www.kernel.org/doc/html/latest/dev-tools/kasan.html) - A dynamic memory error detector for the Linux kernel, similar to AddressSanitizer but tailored for kernel code.
- [KPTR_CHECK (Kernel Pointer Authentication)](https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html) - A kernel boot parameter that enables pointer authentication checks for kernel addresses to prevent kernel pointer leaks.
- [Strict Kernel Memory Permissions](https://www.kernel.org/doc/html/v4.19/security/self-protection.html#strict-kernel-memory-permissions) - Enforces strict permissions on kernel and module memory regions to prevent data execution and memory corruption vulnerabilities.
  - Config options: `CONFIG_STRICT_KERNEL_RWX`, `CONFIG_STRICT_MODULE_RWX`, `CONFIG_DEBUG_ALIGN_RODATA`
- [Kernel Address Space Layout Randomization (KASLR)](https://www.kernel.org/doc/html/v4.19/security/self-protection.html#kernel-address-space-layout-randomization-kaslr) - Randomizes the base address of the kernel's virtual address space to mitigate memory-based attacks.
  - Config option: `CONFIG_RANDOMIZE_BASE`
- [Stack Canary](https://www.kernel.org/doc/html/v4.19/security/self-protection.html#canaries-blinding-and-other-secrets) - Description: Inserts a canary value before the return address on the stack to detect buffer overflow attacks.
  - Config option: `CONFIG_STACK_PROTECTOR`
- [SLUB Allocator Heap Memory Security](https://events.static.linuxfound.org/sites/events/files/slides/slaballocators.pdf) - SLUB allocator is recommended for security due to its improved security features compared to other memory allocators like SLAB and SLOB.

## Return Oriented Programming 
Return-Oriented Programming (ROP) is an advanced exploitation technique used in software security research to construct malicious payloads by chaining together short sequences of code fragments called "gadgets" from existing program code. ROP enables attackers to execute arbitrary code even in the presence of modern security mitigations like DEP and ASLR.

- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - A command-line tool for finding gadgets and building ROP chains.
- [ROPInjector](https://github.com/NytroRST/ROPInjector) - A tool for generating ROP payloads and injecting them into target processes.
- [ROPShell](https://github.com/alpha1ab/ROPShell) - A Python script to assist in the exploitation of buffer overflows using ROP techniques.
- [RP++](https://github.com/0vercl0k/rp) - A ROP gadget discovery tool that parses binaries and provides information about available gadgets.
- [Ropper](https://github.com/sashs/ropper) - Display information about files in different file formats and find gadgets to build rop chains for different architectures (x86/x86_64, ARM/ARM64, MIPS, PowerPC, SPARC64)
- [Pwntools](https://github.com/Gallopsled/pwntools) - pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible

## Data Integrity and Security
### Block Level Encryption
- [dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html) - A Linux kernel feature providing transparent integrity checking of block devices.
- [fs-verity](https://www.kernel.org/doc/html/latest/filesystems/fsverity.html) - A filesystem-level integrity checking feature that works with read-only files and directories.
- [dm-crypt](https://gitlab.com/cryptsetup/cryptsetup/) - A disk encryption mechanism in the Linux kernel, providing block-level encryption for data at rest.
  - Config Option: `CONFIG_DM_CRYPT`
- [Inline Encryption](https://www.kernel.org/doc/html/latest/block/inline-encryption.html) - A feature enabling inline encryption of data stored on block devices.
  - Config Option: `CONFIG_BLK_INLINE_ENCRYPTION`

### Filesystem Level Encryption
- [fscrypt](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html) - A Linux kernel feature for filesystem-level encryption, supporting various filesystems including ext4, F2FS, and UBIFS.
  - Config Options: `CONFIG_ECRYPT_FS`, `CONFIG_FS_ENCRYPTION`
  - User-space tools: [fscryptctl](https://github.com/google/fscryptctl)

### Usage and Implementation Details
- [fscrypt Documentation](https://www.kernel.org/doc/html/latest/filesystems/fscrypt.html) - Official documentation providing details on using fscrypt for filesystem encryption.
- [Cryptsetup Repository](https://gitlab.com/cryptsetup/cryptsetup/) - GitLab repository for cryptsetup, the user-space tool for configuring dm-crypt encryption.
- [Android Security: File-Based Encryption](https://source.android.com/security/encryption/file-based) - Documentation on Android's usage of fscrypt for file-based encryption, used to encrypt data at the directory level.
- [Chrome OS Security: Encrypted User Data](https://chromium.googlesource.com/chromiumos/docs/+/master/security/encrypted_user_data.md) - Overview of Chrome OS's usage of fscrypt for encrypting user data.

### Considerations
- **Integrity Protection**: Note that while dm-verity and fs-verity provide integrity checking, dm-crypt and fscrypt focus on encryption and do not provide integrity protection.
- **Metadata Encryption**: dm-crypt protects all metadata, including extended attributes while fscrypt only encrypts filenames.

## Hardening Yocto
- [Yocto CVE Check Documentation](https://docs.yoctoproject.org/ref-manual/system-updates.html#performing-a-security-vulnerability-scan) - Official documentation providing guidance on performing security vulnerability scans with cve-check in Yocto.
- [Yocto Project Security Advisories](https://www.yoctoproject.org/security/) - Official security advisories and updates for the Yocto Project, complementing cve-check with additional information about vulnerabilities and patches.

## Linux firewalls
- [IPtables](https://netfilter.org/documentation/index.html) - IPtables is a powerful firewall utility in Linux that allows administrators to configure rules for filtering and manipulating network packets at the kernel level. It provides granular control over network traffic based on various criteria such as source/destination IP addresses, ports, and protocols.
- [NFTables](https://wiki.nftables.org/wiki-nftables/index.php/Main_Page) - NFTables is the successor to iptables and provides a more flexible and efficient framework for packet filtering and network address translation (NAT) in Linux. It offers a simpler syntax and improved performance compared to iptables.
- [Firewalld](https://firewalld.org/documentation/) - Firewalld is a dynamic firewall management tool that simplifies the configuration and administration of firewalls in Linux distributions such as Fedora, CentOS, and RHEL. It provides a higher-level abstraction and a more user-friendly interface for managing firewall rules.
- [UFW (Uncomplicated Firewall)](https://help.ubuntu.com/community/UFW) - UFW is a front-end for iptables that aims to make firewall configuration easier for novice users. It provides a simplified command-line interface and predefined application profiles for common services.

## Testing Linux Software for Security
Testing Linux software for security vulnerabilities is crucial to ensure the reliability and integrity of the system. Various testing techniques and tools are available to identify and mitigate potential security risks in Linux applications. Here are some common approaches:

### Static Analysis
Static analysis involves examining the source code or binaries without executing them. It helps identify potential security vulnerabilities, coding errors, and compliance issues early in the development process.
  - [Cppcheck](http://cppcheck.sourceforge.net/) - A static analysis tool for C/C++ code.
  - [Clang Static Analyzer](https://clang-analyzer.llvm.org/) - A static analysis tool based on Clang for C/C++ code.
  - [FindBugs](http://findbugs.sourceforge.net/) - A static analysis tool for Java code.
  - [Brakeman](https://brakemanscanner.org/) - A static analysis tool for Ruby on Rails applications.
  - [Coverity](https://learn.synopsys.com/coverity) - Coverity, now part of Synopsys, is a commercial static analysis tool that provides comprehensive code analysis capabilities for identifying defects, security vulnerabilities, and compliance issues in software projects. It supports multiple programming languages and integrates seamlessly with development workflows.
  - [Klocwork](https://www.perforce.com/manuals/klocwork) - Klocwork is a static analysis tool offered by Perforce that helps developers identify and remediate defects and security vulnerabilities in their codebase. It provides advanced analysis techniques and integrates with popular development environments to streamline the detection and resolution of issues.
  - [SonarQube](https://www.sonarqube.org/) is an open-source platform for continuous inspection of code quality and security. While the basic version is free and open-source, SonarSource offers commercial editions with additional features and support. It supports various programming languages and provides detailed reports on code quality, security vulnerabilities, and more.

### Dynamic Analysis
Dynamic analysis involves executing the software with various inputs to observe its behavior and identify potential vulnerabilities in runtime.
  - [Valgrind](http://valgrind.org/) - A dynamic analysis tool for memory debugging, memory leak detection, and profiling.
  - [GDB](https://www.gnu.org/software/gdb/) - The GNU Debugger, which can be used for dynamic analysis by stepping through code, setting breakpoints, and examining memory.
  - [Strace](https://strace.io/) - A system call tracer that captures and displays system calls made by a program.

### Fuzz Testing
Fuzz-testing involves providing invalid, unexpected, or random data as inputs to the software to uncover bugs and vulnerabilities.
  - [American Fuzzy Lop (AFL)](https://lcamtuf.coredump.cx/afl/) - A popular fuzz-testing tool for finding security vulnerabilities in software.
  - [AFL++](https://github.com/AFLplusplus/AFLplusplus) - AFL++ is an improved version of AFL with additional features and enhancements for better fuzz testing capabilities.
  - [Peach Fuzzer](https://peachfuzzer.com/) - A platform for fuzz-testing software applications, protocols, and file formats.

### Linux Kernel Fuzzers
  - [Trinity](https://github.com/kernelslacker/trinity) - Trinity is a syscall fuzzer specifically designed for the Linux kernel. It generates random system calls and their arguments to stress-test the kernel's interface and uncover potential bugs.
  - [syzkaller](https://github.com/google/syzkaller) - Syzkaller is another Linux kernel fuzzer developed by Google. It systematically generates and executes system call sequences to explore the kernel's behavior and identify vulnerabilities.

### Sanitizers
Sanitizers are runtime tools that detect various types of bugs and vulnerabilities, such as memory errors, data races, and undefined behavior.
  - [AddressSanitizer (ASan)](https://clang.llvm.org/docs/AddressSanitizer.html) - Detects memory corruption bugs, such as buffer overflows and use-after-free errors.
  - [ThreadSanitizer (TSan)](https://clang.llvm.org/docs/ThreadSanitizer.html) - Detects data races and synchronization issues in multithreaded programs.
  - [UndefinedBehaviorSanitizer (UBSan)](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) - Detects undefined behavior in C/C++ programs.

### Cyclomatic Complexity
Cyclomatic Complexity (CC) is a simple metric for quantifying the complexity of a program by measuring the number of linearly independent paths through its source code. It helps identify areas of code that may be difficult to understand, test, or maintain.
  - [Lizard](https://github.com/terryyin/lizard) - Lizard is a command-line tool that analyzes code and generates reports on Cyclomatic Complexity and other metrics. It supports various programming languages, including C/C++, Java, Python, and more.

## Lockdown
Lockdown is a security feature in the Linux kernel designed to prevent unauthorized access to a running kernel image and enhance system security. Here are the key aspects of Lockdown:

### Disabled/Restricted Access
Lockdown disables or restricts access to certain critical kernel interfaces and resources, including:
  - `/dev/mem`, `/dev/kmem`, `/dev/kcore`, and `/dev/ioports`: Direct memory and I/O port access are disabled to prevent unauthorized manipulation of system memory and hardware.
  - BPF (Berkeley Packet Filter) and kprobes: These powerful kernel features are restricted to prevent potential abuse or exploitation.
  - debugfs: Debugging interfaces are disabled to prevent unauthorized access to kernel internals.

### Signed Kernel Modules
  - Lockdown requires that kernel modules be signed or appraised by the Integrity Measurement Architecture (IMA) before they can be loaded into the kernel. This ensures that only trusted and verified modules are allowed to execute, reducing the risk of malicious code injection.

### IMA Secure Boot Rules
  - Lockdown may enforce "secure_boot" rules in the Integrity Measurement Architecture (IMA) policy. These rules ensure that only signed and trusted code is executed during the boot process, enhancing the overall security of the system.
