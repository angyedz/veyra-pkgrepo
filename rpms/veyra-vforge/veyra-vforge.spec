Name:           veyra-vforge
Version:        0.1.0
Release:        2%{?dist}
Summary:        Persistent isolated development environments for Veyra Linux
License:        LicenseRef-Veyra
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
Requires:       python3
Requires:       util-linux

%description
vforge creates persistent development environments from the read-only Veyra
EROFS system root using native OverlayFS and Linux namespaces.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -Dpm0755 usr/bin/vforge %{buildroot}%{_bindir}/vforge

%files
%{_bindir}/vforge

%changelog
* Mon Oct 26 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-2
- Replace the Podman runtime with native OverlayFS environments.

* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Package the Veyra environment manager from its committed source tree.
