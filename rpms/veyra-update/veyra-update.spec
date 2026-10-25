Name:           veyra-update
Version:        0.1.0
Release:        1%{?dist}
Summary:        Atomic system update integration for Veyra Linux
License:        LicenseRef-Veyra
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires:       veyra-vpkg

%description
Provides Veyra's systemd-sysupdate client, signed A/B transfer definitions,
and boot-completion hooks for coordinating OTA and vpkg generations.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -Dpm0755 usr/bin/veyra-update %{buildroot}%{_bindir}/veyra-update
install -Dpm0644 usr/lib/sysupdate.d/10-root-verity.transfer %{buildroot}%{_prefix}/lib/sysupdate.d/10-root-verity.transfer
install -Dpm0644 usr/lib/sysupdate.d/20-root.transfer %{buildroot}%{_prefix}/lib/sysupdate.d/20-root.transfer
install -Dpm0644 usr/lib/sysupdate.d/99-uki.transfer %{buildroot}%{_prefix}/lib/sysupdate.d/99-uki.transfer
install -Dpm0644 usr/lib/tmpfiles.d/veyra-update.conf %{buildroot}%{_prefix}/lib/tmpfiles.d/veyra-update.conf
install -Dpm0644 usr/lib/systemd/system/boot-complete.target.d/veyra.conf %{buildroot}%{_unitdir}/boot-complete.target.d/veyra.conf
install -Dpm0644 usr/lib/systemd/system/systemd-bless-boot.service.d/veyra-vpkg-ota.conf %{buildroot}%{_unitdir}/systemd-bless-boot.service.d/veyra-vpkg-ota.conf
install -Dpm0644 usr/lib/systemd/system/veyra-vpkg-sync.service.d/veyra-ota.conf %{buildroot}%{_unitdir}/veyra-vpkg-sync.service.d/veyra-ota.conf

%files
%{_bindir}/veyra-update
%{_prefix}/lib/sysupdate.d/10-root-verity.transfer
%{_prefix}/lib/sysupdate.d/20-root.transfer
%{_prefix}/lib/sysupdate.d/99-uki.transfer
%{_prefix}/lib/tmpfiles.d/veyra-update.conf
%{_unitdir}/boot-complete.target.d/veyra.conf
%{_unitdir}/systemd-bless-boot.service.d/veyra-vpkg-ota.conf
%{_unitdir}/veyra-vpkg-sync.service.d/veyra-ota.conf

%changelog
* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Package the Veyra A/B update client and systemd-sysupdate configuration.
