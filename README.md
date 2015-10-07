Attempt to provide a kickstart file for CentOS 7 which provides a starting point for a Linux admin to build a host which meets the CIS CentOS 7 benchmarks

Aforementioned CIS benchmarks should be able to be found here https://benchmarks.cisecurity.org/tools2/linux/CIS_CentOS_Linux_7_Benchmark_v1.1.0.pdf

I'm not affliated with the Center for Internet Security in any way.
Use any material from this repository at your own risk.  Don't come crying to me if it causes you any problems.

A minimal kickstart file (minimal-ks.cfg) is provided so people can test their setup (PXE/DHCP etc) with a minimal amount of configuration going on.

centos7-cis-ks.cfg will need extensive customising to suit a particular user's environment.  There's a lot of config in there because it suits me. e.g. CIS 6.4 /etc/securetty, change it to suit yourself. 
I'm not trying to suggest any best practices here, just supply a file which makes it easier to meet the CIS benchmarks.

Sometimes the CIS benchmarks specify a piece of configuration which comes as standard in the default CentOS install.
In centos7-cis-ks.cfg there is some inconsistency of method in that occasionally I've specified these 'default' pieces of config anyway as I don't think it'll do any harm and other times I haven't.

Feel free to get in touch about this.  Particularly with any errors or bugs!

Ross Hamilton <ross.x.hamilton AT gmail.com>
