Name:           hiawatha
Version:        VERSION
Release:        1%{?dist}
Summary:        Hiawatha, an advanced and secure webserver for Unix
Group:          Applications/Internet
License:        GPLv2
URL:            https://hiawatha.leisink.net/
Source0:        https://hiawatha.leisink.net/files/%{name}-%{version}.tar.gz
Patch0:         nobody-99.patch

BuildRoot:      %{_topdir}/BUILDROOT/
BuildRequires:  make,gcc,glibc-devel,libxml2-devel,libxslt-devel,libnghttp2-devel
Requires:       libxml2,libxslt

%description
Hiawatha is a webserver with the three key attributes: secure, easy-to-use, and lightweight.

%prep
%setup -q
%patch 0 -p1

%build
CFLAGS="${CFLAGS:-%optflags}" ; export CFLAGS
CXXFLAGS="${CXXFLAGS:-%optflags}" ; export CXXFLAGS
FFLAGS="${FFLAGS:-%optflags}" ; export FFLAGS
cmake -DCMAKE_INSTALL_PREFIX="" -DCMAKE_INSTALL_LIBDIR=%{_libdir} -DCMAKE_INSTALL_SBINDIR=%{_sbindir} \
      -DCMAKE_INSTALL_SYSCONFDIR=%{_sysconfdir} -DCMAKE_INSTALL_MANDIR=%{_mandir} \
      -DENABLE_TOMAHAWK=ON -DENABLE_MONITOR=ON -DENABLE_SANDBOX=ON -DENABLE_HTTP2=ON
%__make %{?_smp_mflags}

%install
rm -rf %{buildroot}
mkdir -p  %{buildroot}
%__make install DESTDIR=%{buildroot}
mkdir -p %{buildroot}%{_defaultdocdir}/hiawatha
cp ChangeLog %{buildroot}%{_defaultdocdir}/hiawatha
mkdir -p %{buildroot}%{_initrddir}
cp extra/redhat/hiawatha %{buildroot}%{_initrddir}
sed -i "s/#ServerId/ServerId/" %{buildroot}%{_sysconfdir}/hiawatha/hiawatha.conf

%post
getent group www-data >/dev/null || groupadd -r www-data
getent passwd www-data >/dev/null || \
	useradd -r -g www-data -d /var/www -s /sbin/nologin \
	-c "Web server user" www-data
chkconfig --add hiawatha
if [ "$1" = 1 ]; then
	service hiawatha start
else
	service hiawatha restart
fi
exit 0

%preun
if [ "$1" = 0 ]; then
	service hiawatha stop
	chkconfig --del hiawatha
fi
exit 0

%clean
rm -rf %{buildroot}

%files
%attr(555, root, root) %{_bindir}/
%attr(555, root, root) %{_sbindir}/
%attr(-, root, root) %{_libdir}/hiawatha/
%attr(-, root, root) %{_mandir}/
%attr(-, root, root) %{_localstatedir}/log/hiawatha/
%attr(-, root, root) %{_localstatedir}/www/hiawatha/
%attr(-, root, root) %{_defaultdocdir}/hiawatha/
%attr(-, root, root) %{_initrddir}/
%config %{_sysconfdir}/hiawatha

%changelog
