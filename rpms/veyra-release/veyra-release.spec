Name:           veyra-release
Version:        0.1.0
Release:        1%{?dist}
Summary:        Basic release information for Veyra Linux pre-alpha
License:        MIT
BuildArch:      noarch
Source0:        release.txt
Source1:        LICENSE

%description
Provides a small, human-readable release marker for Veyra Linux. It is a
Veyra-specific add-on package and does not replace Fedora system packages.

%prep

%build

%install
install -Dpm0644 %{SOURCE0} %{buildroot}%{_datadir}/veyra/release
install -Dpm0644 %{SOURCE1} %{buildroot}%{_licensedir}/%{name}/LICENSE

%files
%license %{_licensedir}/%{name}/LICENSE
%{_datadir}/veyra/release

%changelog
* Sun Oct 25 2026 Veyra contributors <packages@veyra.invalid> - 0.1.0-1
- Add the first Veyra RPM repository smoke-test package.
