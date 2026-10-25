Name:           veyra-v-dri
Version:        0.1.0
Release:        1%{?dist}
Summary:        Read-only hardware and driver diagnostics for Veyra Linux
License:        LicenseRef-Veyra
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
Requires:       kmod
Requires:       python3

%description
Detects PCI display and network devices, reports bound drivers, checks
kernel-module compatibility, and explains driver-related findings. This
initial release is read-only and never loads or installs a kernel module.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -Dpm0755 usr/bin/v-dri %{buildroot}%{_bindir}/v-dri
install -Dpm0644 share/doc/v-dri-architecture.md %{buildroot}%{_docdir}/%{name}/v-dri-architecture.md

%files
%{_bindir}/v-dri
%doc %{_docdir}/%{name}/v-dri-architecture.md

%changelog
* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Add read-only device, module compatibility, and signature-policy diagnostics.
