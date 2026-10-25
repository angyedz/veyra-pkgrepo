Name:           veyra-vpkg
Version:        0.1.0
Release:        1%{?dist}
Summary:        Native RPM package manager for Veyra Linux
License:        LicenseRef-Veyra
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
Requires:       libdnf5
Requires:       gnupg2
Requires:       python3
Requires:       python3-libdnf5
Requires:       rpm
Requires:       systemd

%description
vpkg manages supported Veyra RPM transactions through the libdnf5 API and
keeps the DNF command-line client out of the Veyra host image.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -Dpm0755 usr/bin/vpkg %{buildroot}%{_bindir}/vpkg
install -Dpm0644 usr/lib/veyra/vpkg_libdnf.py %{buildroot}%{_libdir}/veyra/vpkg_libdnf.py
install -Dpm0644 usr/lib/veyra/veyra_repo.py %{buildroot}%{_libdir}/veyra/veyra_repo.py
install -Dpm0644 usr/share/veyra/RPM-GPG-KEY-VEYRA %{buildroot}%{_datadir}/veyra/RPM-GPG-KEY-VEYRA
install -Dpm0644 usr/share/veyra/vpkg/protected-core.json %{buildroot}%{_datadir}/veyra/vpkg/protected-core.json
install -Dpm0644 etc/yum.repos.d/veyra-main.repo %{buildroot}%{_sysconfdir}/yum.repos.d/veyra-main.repo
install -Dpm0644 etc/yum.repos.d/veyra-testing.repo %{buildroot}%{_sysconfdir}/yum.repos.d/veyra-testing.repo
install -Dpm0644 usr/lib/systemd/system/veyra-vpkg-check.service %{buildroot}%{_unitdir}/veyra-vpkg-check.service
install -Dpm0644 usr/lib/systemd/system/veyra-vpkg-sync.service %{buildroot}%{_unitdir}/veyra-vpkg-sync.service
install -Dpm0644 usr/lib/systemd/system/systemd-boot-check-no-failures.service.d/veyra-vpkg.conf %{buildroot}%{_unitdir}/systemd-boot-check-no-failures.service.d/veyra-vpkg.conf
install -Dpm0644 usr/lib/systemd/system/systemd-sysext.service.d/veyra-vpkg.conf %{buildroot}%{_unitdir}/systemd-sysext.service.d/veyra-vpkg.conf
install -Dpm0644 usr/lib/systemd/system/boot-complete.target.d/veyra-vpkg.conf %{buildroot}%{_unitdir}/boot-complete.target.d/veyra-vpkg.conf
install -Dpm0644 usr/lib/systemd/system-preset/99-veyra-vpkg.preset %{buildroot}%{_prefix}/lib/systemd/system-preset/99-veyra-vpkg.preset

%files
%{_bindir}/vpkg
%{_libdir}/veyra/vpkg_libdnf.py
%{_libdir}/veyra/veyra_repo.py
%{_datadir}/veyra/RPM-GPG-KEY-VEYRA
%{_datadir}/veyra/vpkg/protected-core.json
%config %{_sysconfdir}/yum.repos.d/veyra-main.repo
%config %{_sysconfdir}/yum.repos.d/veyra-testing.repo
%{_unitdir}/veyra-vpkg-check.service
%{_unitdir}/veyra-vpkg-sync.service
%{_unitdir}/systemd-boot-check-no-failures.service.d/veyra-vpkg.conf
%{_unitdir}/systemd-sysext.service.d/veyra-vpkg.conf
%{_unitdir}/boot-complete.target.d/veyra-vpkg.conf
%{_prefix}/lib/systemd/system-preset/99-veyra-vpkg.preset

%changelog
* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Package vpkg and its libdnf5 runtime integration.
