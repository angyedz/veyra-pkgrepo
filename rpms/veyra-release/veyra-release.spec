Name:           veyra-release
Version:        0.1.0
Release:        2%{?dist}
Summary:        Fedora 44-compatible Veyra release system extension
License:        MIT
BuildArch:      x86_64
Source0:        veyra-release.raw

%description
Signed optional system extension for the Veyra Next vpkg manager.
The host EROFS base remains unchanged.

%prep

%build

%install
install -D -m 0644 %{SOURCE0} %{buildroot}/var/lib/extensions/veyra-release.raw

%files
/var/lib/extensions/veyra-release.raw
