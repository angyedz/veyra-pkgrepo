Name:           veyra-vforge
Version:        0.1.0
Release:        1%{?dist}
Summary:        Persistent isolated development environments for Veyra Linux
License:        LicenseRef-Veyra
BuildArch:      noarch
Source0:        %{name}-%{version}.tar.gz
Requires:       e2fsprogs
Requires:       fuse-overlayfs
Requires:       podman
Requires:       python3

%description
vforge creates and manages persistent development environments for Veyra
Linux using rootless Podman and fuse-overlayfs.

%prep
%autosetup -n %{name}-%{version}

%build

%install
install -Dpm0755 usr/bin/vforge %{buildroot}%{_bindir}/vforge

%files
%{_bindir}/vforge

%changelog
* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Package the Veyra environment manager from its committed source tree.
