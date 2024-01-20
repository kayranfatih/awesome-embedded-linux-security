# Awesome Embedded Linux Security
A collection of awesome tools, books, resources, software, documents and cool stuff about embedded linux security
[![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

Thanks to all [contributors](https://github.com/kayranfatih/awesome-embedded-linux-security/graphs/contributors). The goal is to build community-driven collection of  well-known resources.

## Contents

## Root of Trusts 
- [OpenTitan](https://opentitan.org/) - OpenTitan is the first open source project building a transparent, high-quality reference design and integration guidelines for silicon root of trust (RoT) chips
## TEE
ARM's TrustZone
RISC-V's MultiZone
Intel SGX)
Commercial
Kinibi
QSEE
iTrustee
Open source 
Trusty
OP-TEE

## Links 
https://www.bytesnap.com/news-blog/embedded-linux-security-secure-iot-devices/

## Secure Boot
## Bootloaders

- [barebox](https://www.barebox.org/) - A bootloader (initially named U-Boot v2) designed for embedded systems.
- [coreboot](https://www.coreboot.org/) - Extended firmware platform that delivers a lightning fast and secure boot experience on modern computers and embedded systems.
- [libreboot](https://libreboot.org/) - coreboot distribution with proprietary software removed.
- [RedBoot](http://ecos.sourceware.org/redboot/) - Complete bootstrap environment for embedded systems.
- [U-Boot](https://www.denx.de/wiki/U-Boot) - The Universal Bootloader.

## Kernel modules

- [AppArmor](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/apparmor.html) - Linux Security Module that provides MAC style security extension for the Linux kernel.
- [LoadPin](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/LoadPin.html) - Linux Security Module that ensures all kernel-loaded files (modules, firmware, etc) all originate from the same filesystem, with the expectation that such a filesystem is backed by a read-only device.
- [SELinux](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/SELinux.html) - Linux Security Module.
- [SMACK](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/Smack.html) - Linux Security Module providing mandatory access control that includes simplicity in its primary design goals.
- [TOMOYO](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/tomoyo.html) - Linux Security Module adding name-based MAC to the Linux kernel.
- [Yama](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/Yama.html) - Linux Security Module that collects system-wide DAC security protections that are not handled by the core kernel itself.

## Init systems

- [dumb-init](https://github.com/Yelp/dumb-init) - A minimal init system for Linux containers.
- [finit](http://troglobit.com/projects/finit/) - Fast init for Linux systems.
- [minit](http://www.fefe.de/minit/) - A small yet feature-complete init.
- [OpenRC](https://github.com/OpenRC/openrc) - Dependency-based init system that works with the system-provided init program.
- [runit](http://smarden.org/runit/) - A UNIX init scheme with service supervision.
- [systemd](https://github.com/systemd/systemd) - The systemd System and Service Manager.
- [upstart](http://upstart.ubuntu.com/) - Event-based init system.

## Operating Systems
- [OpenWRT](https://openwrt.org/) - The OpenWrt Project is a Linux operating system targeting embedded devices. Instead of trying to create a single, static firmware, OpenWrt provides a fully writable filesystem with package management. This frees you from the application selection and configuration provided by the vendor and allows you to customize the device through the use of packages to suit any application
- [Yocto](https://www.yoctoproject.org/) - The Yocto Project (YP) is an open source collaboration project that helps developers create custom Linux-based systems regardless of the hardware architecture. The project provides a flexible set of tools and a space where embedded developers worldwide can share technologies, software stacks, configurations, and best practices that can be used to create tailored Linux images for embedded and IOT devices, or anywhere a customized Linux OS is needed
## MAC and Kernel Modules
## Container Security
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






 









