Attempt to provide a kickstart file for CentOS 7 which provides a starting point for a linux admin to build a host which meets the CIS CentOS 7 benchmarks

Aforementioned CIS benchmarks should be able to be found here https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v1.1.0.pdf

A minimal kickstart file (minimal-ks.cfg) is provided so people can test their setup (PXE/DHCP etc) with the minimal amount of configuration going on.

centos7-cis-ks.cfg will need extensive customising to suit a particular user's environment.  There's a lot of config in there because it suits me. e.g. CIS 6.4 /etc/securetty, change it to suit yourself. 
I'm not trying to suggest any best practices here, just supply a file which makes it easier to meet the CIS requirements.

Sometimes the CIS benchmarks specify a piece of configuration which comes as standard in the default CentOS install.
In centos7-cis-ks.cfg there is some inconsistency of method in that occasionally I've specified these 'default' pieces  of config anyway as I don't think it'll do any harm and other times I haven't.

TODO check/review 7.1.3 PASS_WARN_AGE

Feel free to get in touch about this.  Particularly with any errors or bugs!

Ross Hamilton <ross.x.hamilton AT gmail.com>
