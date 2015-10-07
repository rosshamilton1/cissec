install
lang en_GB.UTF-8
keyboard --vckeymap=gb --xlayouts='gb'
timezone Europe/London --isUtc
auth --useshadow --enablemd5
selinux --disabled
firewall --disabled
services --enabled=NetworkManager,sshd
eula --agreed
ignoredisk --only-use=vda
reboot

bootloader --location=mbr
zerombr
clearpart --all --initlabel
part swap --asprimary --fstype="swap" --size=1024
part /boot --fstype xfs --size=200
part pv.01 --size=1 --grow
volgroup rootvg01 pv.01
logvol / --fstype xfs --name=lv01 --vgname=rootvg01 --size=1 --grow

rootpw qwerty

repo --name=base --baseurl="http://anorien.csc.warwick.ac.uk/mirrors/centos/7/isos/x86_64/"
url --url="http://anorien.csc.warwick.ac.uk/mirrors/centos/7/isos/x86_64/"

%packages --nobase --ignoremissing
@core
%end
