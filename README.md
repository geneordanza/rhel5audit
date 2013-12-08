Automate retrieval of security configuration from Red Hat Enterprise Linux
(RHEL) 5 based off the recommendation from Center for Internet Security.

The rhel5audit utility is divided into two (2) parts. The audit.py for retrieval
of RHEL 5 security configuration and the ciscfg.py for applying the recommended
security settings.  The audit.py uses auditlib.py for most of it variable
definition. For ciscfg.py it uses ciscfglib.py.

The Security Configuration Benchmark is divided into 9 categories:

1. Install Updates, Patches and Additional Security Software
2. OS Services
3. Special Purpose Services
4. Network Configuration and Firewalls
5. Logging and Auditing
6. System Access, Authentication and Authorization
7. User Accounts and Environment
8. Warning Banners
9. System Maintenance

The latest Security Configuration Benchmark for RHEL 5 can found here:
https://benchmarks.cisecurity.org/downloads/show-single/index.cfm?file=rhel5.200

