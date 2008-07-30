# ntlmaps.spec
# Copyright (C) 2004 Darryl Dixon <esrever_otua@pythonhacker.is-a-geek.net>
# This program may be freely redistributed under the terms of the GNU GPL

%define name ntlmaps
%define ver 0.9.9.5
%define rel 1

Summary: NTLMAPS is a proxy server that authenticates requests to Microsoft proxies that require NTLM authentication.
Name: %{name}
Version: %{ver}
Release: %{rel}
License: GPL
Group: Applications/Internet
URL: http://ntlmaps.sourceforge.net
Vendor: Dmitry Rozmanov, Darryl Dixon, and others
Source: http://prdownloads.sourceforge.net/%{name}/%{name}-%{version}.tar.gz
Packager: Darryl Dixon <esrever_otua@pythonhacker.is-a-geek.net>
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
BuildRequires: python >= 1.5.2 perl
Requires: python >= 1.5.2

%description
NTLM Authorization Proxy Server (ntlmaps) is a proxy software that allows
you to authenticate via a Microsoft Proxy Server using the proprietary NTLM
protocol. NTLMAPS has the ability to behave as a standalone proxy server and
authenticate HTTP clients at Web servers using the NTLM protocol. It can
change arbitrary values in your client's request headers so that those
requests will look like they were created by Microsoft Internet Explorer.  It
is written in Python 1.5.2.

%prep

%setup

%build

%install
if [ -d $RPM_BUILD_ROOT ]; then rm -rf $RPM_BUILD_ROOT; fi
%define ntlmaps_dir /opt/ntlmaps
# This can be vastly improved, but it Works For Now!(tm)   ;)
mkdir -p $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{ntlmaps_dir}
mkdir -p $RPM_BUILD_ROOT%{ntlmaps_dir}/lib
mkdir -p $RPM_BUILD_ROOT%{ntlmaps_dir}/doc
mkdir -p $RPM_BUILD_ROOT%{ntlmaps_dir}/packaging
mkdir -p $RPM_BUILD_ROOT%{_bindir}
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/%{name}
install --mode=0755 --group=root --owner=root main.py \
                                              runserver.bat \
                                              COPYING \
                                              __init__.py \
                                              $RPM_BUILD_ROOT%{ntlmaps_dir}
install --mode=0755 --group=root --owner=root server.cfg \
                                              $RPM_BUILD_ROOT%{_sysconfdir}/%{name}
install --mode=0755 --group=root --owner=root lib/* $RPM_BUILD_ROOT%{ntlmaps_dir}/lib
install --mode=0755 --group=root --owner=root doc/* $RPM_BUILD_ROOT%{ntlmaps_dir}/doc
install --mode=0755 --group=root --owner=root packaging/* $RPM_BUILD_ROOT%{ntlmaps_dir}/packaging
# Point the default config directory to /var/opt/ntlmaps:
perl -pi -e 's&(^conf.*?)__init__.*?(\)\)$)&\1"%{_sysconfdir}/%{name}/"\2&' $RPM_BUILD_ROOT%{ntlmaps_dir}/main.py
$RPM_BUILD_ROOT%{ntlmaps_dir}/packaging/compile.py $RPM_BUILD_ROOT%{ntlmaps_dir}
$RPM_BUILD_ROOT%{ntlmaps_dir}/packaging/compile.py $RPM_BUILD_ROOT%{ntlmaps_dir}/lib
ln -s $PYTHON_SITE%{ntlmaps_dir}/main.py $RPM_BUILD_ROOT%{_bindir}/ntlmaps
#mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1
#install --mode=0644 --group=root --owner=root ntlmaps.1 $RPM_BUILD_ROOT%{_mandir}/man1
#gzip $RPM_BUILD_ROOT%{_mandir}/man1/ntlmaps.1

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root)
/opt/*
#%{_libdir}/*
%{_bindir}/*
#%{_mandir}/*
%{_sysconfdir}/*

%changelog
* Fri Jun 10 2005 Darryl Dixon <esrever_otua@pythonhacker.is-a-geek.net>
  [ntlmaps-0.9.9.4]
- Move server.cfg to %{_sysconfdir} for better FHS compliance

* Thu Feb 24 2005 Darryl Dixon <esrever_otua@pythonhacker.is-a-geek.net>
  [ntlmaps-0.9.9.3]
- Update for moved file locations in source dir
- Use %{ntlmaps_dir}
- Move server.cfg to %{_localstatedir}%{ntlmaps_dir} (/var/opt/ntlmaps)

* Wed Feb 23 2005 Darryl Dixon <esrever_otua@pythonhacker.is-a-geek.net>
  [ntlmaps-0.9.9.2]
- Initial release of .spec file
