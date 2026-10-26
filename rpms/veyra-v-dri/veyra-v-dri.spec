Name:           veyra-v-dri
Version:        0.1.0
Release:        2%{?dist}
Summary:        Read-only graphics driver status diagnostics for Veyra Linux
License:        LicenseRef-Veyra
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
Requires:       python3

%description
Reports DRM devices, their bound Fedora kernel drivers, and the current
kernel module signature-enforcement state. This package does not install,
load, sign, or activate drivers.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -Dpm0755 usr/bin/v-dri %{buildroot}%{_bindir}/v-dri
install -Dpm0644 share/doc/v-dri.md %{buildroot}%{_docdir}/%{name}/v-dri.md

%files
%{_bindir}/v-dri
%doc %{_docdir}/%{name}/v-dri.md

%changelog
* Mon Oct 26 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-2
- Sync schema-2 driver status with Fedora 44 module-signature enforcement.

* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Add read-only device and module compatibility diagnostics.
