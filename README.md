# Awesome Embedded Linux Security
A collection of awesome tools, books, resources, software, documents and cool stuff about embedded linux security
[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

Thanks to all [contributors](https://github.com/kayranfatih/awesome-embedded-linux-security/graphs/contributors). The goal is to build community-driven collection of  well-known resources.

## Contents

DICE, TPM, TCG

## Root of Trusts 
- [OpenTitan](https://opentitan.org/) - OpenTitan is the first open source project building a transparent, high-quality reference design and integration guidelines for silicon root of trust (RoT) chips
- [Project Cerberus](https://github.com/Azure/Project-Cerberus) - Project Cerberus is designed to be a hardware root of trust (RoT) for server platforms. It provides functionality to enforce secure boot for firmware on devices with or without intrinsic secure boot capabilities. It also provides a mechanism to securely attest to the state of the device firmware.
  
## TEE

- [ARM TrustZone](https://www.arm.com/technologies/trustzone-for-cortex-m) - TrustZone technology for Arm Cortex-M processors enables robust levels of protection at all cost points for IoT devices. The technology reduces the potential for attack by isolating the critical security firmware, assets and private information from the rest of the application.
- [RISC-V Keystone](https://keystone-enclave.org/) - Keystone is an open-source project for building customizable trusted execution environments (TEEs) based on RISC-V for various platforms and use cases. 
- [OP-TEE](https://www.trustedfirmware.org/projects/op-tee/) - OP-TEE is an open-source TEE designed for ARM TrustZone. It provides a secure and efficient environment for running trusted applications on ARM processors, implementing the GlobalPlatform TEE system architecture and APIs.
- [Intel SGX (Software Guard Extensions)](https://github.com/intel/linux-sgx) - Intel SGX is a set of security-related instruction codes that are built into modern Intel CPUs. It allows applications to create secure enclaves for code and data. While SGX itself is not open-source, there are open-source SDKs and tools for developing SGX applications.
- [AMD SEV (Secure Encrypted Virtualization](https://github.com/AMDESE/AMDSEV) -  AMD SEV is a technology that provides encryption for virtual machine memory. It helps protect VMs from attacks and unauthorized access. While SEV is a hardware feature, there are open-source tools and frameworks for leveraging SEV in virtualized environments.

## Links 
https://www.bytesnap.com/news-blog/embedded-linux-security-secure-iot-devices/

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

## MAC and Kernel modules

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

## Init systems

- [dumb-init](https://github.com/Yelp/dumb-init) - A minimal init system for Linux containers.
- [finit](http://troglobit.com/projects/finit/) - Fast init for Linux systems.
- [minit](http://www.fefe.de/minit/) - A small yet feature-complete init.
- [OpenRC](https://github.com/OpenRC/openrc) - Dependency-based init system that works with the system-provided init program.
- [runit](http://smarden.org/runit/) - A UNIX init scheme with service supervision.
- [systemd](https://github.com/systemd/systemd) - The systemd System and Service Manager.
- [upstart](http://upstart.ubuntu.com/) - Event-based init system.

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

### Community
- [Docker Community Forums](https://forums.docker.com/c/security/19) - Official Docker community forums for discussing container security topics and seeking assistance.
- [Kubernetes Slack](https://slack.k8s.io/) - Join the Kubernetes Slack workspace to engage with the community and discuss security-related topics in real-time.
- [Container Security Reddit](https://www.reddit.com/r/ContainerSecurity/) - Subreddit dedicated to discussions about container security, vulnerability management, and best practices.


## Kernel Memory Protection
- []()
- CONFIG_STRICT_KERNEL_RWX, CONFIG_STRICT_MODULE_RWX, CONFIG_DEBUG_ALIGN_RODATA : https://www.kernel.org/doc/html/v4.19/security/self-protection.html#strict-kernel-memory-permissions
- KASLR : https://www.kernel.org/doc/html/v4.19/security/self-protection.html#kernel-address-space-layout-randomization-kaslr (CONFIG_RANDOMIZE_BASE)
- Stack Canary - CONFIG_STACK_PROTECTOR : https://www.kernel.org/doc/html/v4.19/security/self-protection.html#canaries-blinding-and-other-secrets
- Heap Memory : chrome-extension://efaidnbmnnnibpcajpcglclefindmkaj/https://events.static.linuxfound.org/sites/events/files/slides/slaballocators.pdf SLUB best for security


## Host-based Intrusion Detection Systems

- [AIDE](https://aide.github.io/) - Advanced Intrusion Detection Environment, a file and directory integrity checker.
- [afick](http://afick.sourceforge.net/) - Another File Integrity Checker, monitors changes on the file system and detects intrusions.
- [chrootkit](http://www.chkrootkit.org/) - Checks for rootkits.
- [Open Source Tripwire](https://github.com/Tripwire/tripwire-open-source) - Security and data integrity tool for monitoring and alerting on file & directory changes.
- [OSSEC](https://www.ossec.net/) - The World’s Most Widely Used Host-based Intrusion Detection System.
- [rkhunter](http://rkhunter.sourceforge.net/) - A rootkit hunter.
- [SAMHAIN](https://la-samhna.de/samhain/) - Provides file integrity checking and log file monitoring/analysis, as well as rootkit detection, port monitoring, detection of rogue SUID executables, and hidden processes. 


![image](https://github.com/kayranfatih/awesome-embedded-linux-security/assets/18244664/5562d92e-3dd3-470e-97aa-abd33ea56120)


## Return Oriented Programming 
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - This tool lets you search your gadgets on your binaries to facilitate your ROP exploitation. ROPgadget supports ELF/PE/Mach-O/Raw formats on x86, x64, ARM, ARM64, PowerPC, SPARC, MIPS, RISC-V 64, and RISC-V Compressed architectures
- [Ropper](https://github.com/sashs/ropper) - Display information about files in different file formats and find gadgets to build rop chains for different architectures (x86/x86_64, ARM/ARM64, MIPS, PowerPC, SPARC64)
- [Pwntools](https://github.com/Gallopsled/pwntools) - pwntools is a CTF framework and exploit development library. Written in Python, it is designed for rapid prototyping and development, and intended to make exploit writing as simple as possible
## Data Integrity and Security
- dm-verity
- fs-verity
- dm-crypt
- Block level 
CONFIG_BLK_INLINE_ENCRYPTION
CONFIG_DM_CRYPT (dm-crypt)
Requires https://gitlab.com/cryptsetup/cryptsetup/
- fscrypt
Filesystem level
CONFIG_ECRYPT_FS (ecryptfs stacking filesystem)
CONFIG_FS_ENCRYPTION (fscrypt)
built into ext4, F2FS, UBIFS
user-space tools for embedded systems at https://github.com/google/fscryptctl;
More information at https://www.kernel.org/doc/html/latest/filesystems/fscrypt.htm
-Fscrypt used for Android and ChromeOS. Encrypts at the directory level.
eMMC operates at the block level
Dm-crypt protects all metadata (including xattr). Fscrypt only encrypts filenames.
None of these provide integrity

## Containers and sandboxing
Seccomp
Seccomp-bpf - seccomp-bpf is an extension to seccomp that allows bpf filtering of syscalls
Landlock LSM - Landlock is a stackable LSM designed to help with the creation of security sandboxes, Limits the security impact of vulnerabilities in userspace applications https://www.kernel.org/doc/html/latest/userspace-api/landlock.html
Filesystem binding
Linux containers
Linux cgroups and namespaces

## Hardening Yocto
Yocto security hardening
Using cve-check

## Linux Security Modules
The Linux Security Module Framework
Access control models
Comparing LSMs
The Lockdown LSM
AppArmor

## Testing Linux software for security
Static analysis
Dynamic analysis
Fuzz-testing
Sanitizers
Complexity analysis

## Linux firewalls
- IPtables
- Nftables

## Access control models
- Discretionary (DAC)
- Mandatory (MAC)
- Role-Based (RBAC)

Simplified Mandatory Access Control Kernel Support (SMACK) [CONFIG_SECURITY_SMACK] - MAC system using labels. Labels on objects are required to match task labels
TOMOYO [CONFIG_SECURITY_TOMOYO] - MAC with process monitoring. Not well maintained
AppArmor [CONFIG_SECURITY_APPARMOR]- MAC-like with task profiles. Tasks without profiles run with normal Linux DAC permissions.
Yama [CONFIG_SECURITY_YAMA] - Adds ptrace restrictions
Lockdown [CONFIG_SECURITY_LOCKDOWN_LSM] - Enforces coarse lockdown
SELinux [CONFIG_SECURITY_SELINUX] - MAC. Heavyweight and more appropriate for PCs
LoadPin [CONFIG_SECURITY_LOADPIN] - Ensures all kernel-loaded files (modules, firmware) all originate from same (verified, ro) filesystem
Landlock [CONFIG_SECURITY_LANDLOCK] - Provides sandbox access control of kernel objects


## Lockdown prevents access to a running kernel image
The following are disabled/restricted:
/dev/mem, /dev/kmem,/dev/kcore,/dev/ioports
BPF
kprobes
debugfs
Kernel modules must be signed or IMA appraised

IMA requires "secure_boot" rules to the policy

## Static Analysis
Open source tools:
cppcheck (https://cppcheck.sourceforge.io/)
clang static analyzer (https://clang-analyzer.llvm.org/)

Commercial tools:
Coverity
Klocwork
SonarQube

## RUNTIME PROTECTIONS

## Dynamic Analysis
Memory analysis (userspace applications):
valgrind (good for finding allocator problems)
AddressSanitizer (ASan) is an instrumentation tool created by Google security researchers to identify memory access problems in C and C++ programs.

Kernel Address Sanitizer (KASAN)
Dynamic memory error detector for the Linux kernel
Only supported for x86_64 and arm64
Enable with CONFIG_KASAN=y
Works with SLAB and SLUB
https://www.kernel.org/doc/html/v4.12/dev-tools/kasan.html

Kernel Concurrency Sanitizer (KCSAN)
Dynamic race-condition detector for Linux kernel
In kernel since version 5.8
Requires >= GCC 11 or Clang 11
Enable with CONFIG_KSCAN
https://www.kernel.org/doc/html/latest/dev-tools/kcsan.html

Kernel Electric Fence (KFENCE)
Memory safety error detector
Detects heap out-of-bounds access, use-after-free, invalid-free
may be suitable for production deployment
Enable with CONFIG_KFENCE
https://www.kernel.org/doc/html/latest/dev-tools/kfence.html

## Fuzz Testing 
Open source: AFL (https://github.com/google/AFL)
Commerical: BeSTORM (https://beyondsecurity.com/solutions/bestorm-dynamic-application-security-testing.html)
The Linux Kernel has a syscall fuzzer called Trinity
(https://github.com/kernelslacker/trinity)
 syzkaller (Linux kernel fuzzer)

## Complexity analysis
- Cyclomatic Complexity (CC) is simple metric for complexity
- https://github.com/terryyin/lizard 






 









