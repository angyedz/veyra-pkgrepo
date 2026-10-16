import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ApplicationWindow {
    id: window
    visible: true
    width: 1040
    height: 720
    minimumWidth: 720
    minimumHeight: 480
    title: "Veyra AppCenter"
    color: "#10141e"
    property bool installedMode: false

    function currentSource() { return sourceBox.currentIndex === 0 ? "apk" : "nix" }
    function runSearch() {
        installedMode = false
        backend.search(searchBox.text, currentSource())
    }
    function showInstalled() {
        installedMode = true
        backend.installed(currentSource())
    }

    header: Rectangle {
        height: 84
        color: "#161d2b"
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 28
            anchors.rightMargin: 28
            spacing: 20
            ColumnLayout {
                Layout.alignment: Qt.AlignVCenter
                spacing: 1
                Label { text: "Veyra"; color: "#fafcff"; font.bold: true; font.pixelSize: 25 }
                Label { text: "APPLICATION CENTER"; color: "#9ba9c3"; font.pixelSize: 10; font.letterSpacing: 2 }
            }
            Item { Layout.fillWidth: true }
            Label { text: "GLACIER  /  1.0"; color: "#a6b6cf"; font.pixelSize: 12 }
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        Rectangle {
            Layout.fillHeight: true
            Layout.preferredWidth: 210
            color: "#151b28"
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 18
                spacing: 12
                Label {
                    text: "LIBRARY"
                    color: "#8191ad"
                    font.bold: true
                    font.pixelSize: 11
                    Layout.topMargin: 10
                }
                Button {
                    Layout.fillWidth: true
                    text: "Discover"
                    highlighted: !installedMode
                    onClicked: window.runSearch()
                }
                Button {
                    Layout.fillWidth: true
                    text: "Installed"
                    highlighted: installedMode
                    onClicked: window.showInstalled()
                }
                Rectangle {
                    Layout.topMargin: 20
                    Layout.fillWidth: true
                    height: 1
                    color: "#30394a"
                }
                Label {
                    text: "PACKAGE SOURCE"
                    color: "#8191ad"
                    font.pixelSize: 11
                    font.bold: true
                }
                ComboBox {
                    id: sourceBox
                    Layout.fillWidth: true
                    model: backend.nixAvailable ? ["Alpine / Veyra", "Nix packages"] : ["Alpine / Veyra"]
                    onActivated: {
                        if (window.installedMode) window.showInstalled()
                        else if (searchBox.text.trim().length > 0) window.runSearch()
                    }
                }
                Label {
                    text: "APK packages are verified\nusing trusted signing keys.\nNix runs as your user."
                    color: "#8c9ab1"
                    font.pixelSize: 11
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                }
                Item { Layout.fillHeight: true }
                Button {
                    Layout.fillWidth: true
                    text: "Refresh index"
                    enabled: !backend.busy
                    onClicked: backend.refresh(window.currentSource())
                }
                Label {
                    text: "Veyra Linux"
                    color: "#66738a"
                    font.pixelSize: 11
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.leftMargin: 28
            Layout.rightMargin: 28
            Layout.topMargin: 25
            Layout.bottomMargin: 20
            spacing: 17
            Label {
                text: installedMode ? "Your applications" : "Explore applications"
                color: "#f6f8fd"
                font.pixelSize: 29
                font.bold: true
            }
            Label {
                text: installedMode ? "Packages currently installed from the selected source" : "Find apps across the repositories you trust"
                color: "#a8b6ca"
                font.pixelSize: 13
            }
            RowLayout {
                Layout.fillWidth: true
                spacing: 10
                TextField {
                    id: searchBox
                    Layout.fillWidth: true
                    placeholderText: "Search for a package (e.g. firefox)"
                    enabled: !backend.busy
                    onAccepted: window.runSearch()
                }
                Button {
                    text: "Search"
                    enabled: !backend.busy && searchBox.text.trim().length > 0
                    highlighted: true
                    onClicked: window.runSearch()
                }
            }
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
                color: "#30394a"
            }
            BusyIndicator {
                running: backend.busy
                visible: running
                Layout.alignment: Qt.AlignHCenter
            }
            ListView {
                id: packageList
                Layout.fillWidth: true
                Layout.fillHeight: true
                clip: true
                spacing: 9
                model: backend.results
                ScrollBar.vertical: ScrollBar {}
                delegate: Rectangle {
                    width: packageList.width - 12
                    height: 86
                    radius: 12
                    color: pick.containsMouse ? "#27354a" : "#1d2838"
                    border.color: "#2c3a4d"
                    property var pkg: modelData
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 20
                        anchors.rightMargin: 20
                        spacing: 14
                        Rectangle {
                            width: 44
                            height: 44
                            radius: 12
                            color: "#344f7d"
                            Label {
                                anchors.centerIn: parent
                                text: pkg.name.length ? pkg.name.charAt(0).toUpperCase() : "?"
                                font.pixelSize: 20
                                font.bold: true
                                color: "white"
                            }
                        }
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 3
                            Label {
                                text: pkg.name
                                color: "#f1f5ff"
                                font.bold: true
                                font.pixelSize: 16
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                            Label {
                                text: pkg.description || "Application package"
                                color: "#9aaec7"
                                font.pixelSize: 12
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }
                        Label {
                            text: pkg.version || pkg.source.toUpperCase()
                            color: "#9eb8ea"
                            font.pixelSize: 12
                        }
                        Label { text: "›"; color: "#dae7ff"; font.pixelSize: 25 }
                    }
                    MouseArea {
                        id: pick
                        anchors.fill: parent
                        hoverEnabled: true
                        onClicked: { details.pkg = parent.pkg; details.open() }
                    }
                }
                Label {
                    anchors.centerIn: parent
                    visible: packageList.count === 0 && !backend.busy
                    text: "Search to discover packages, or select Installed."
                    color: "#8292ab"
                }
            }
            Label {
                Layout.fillWidth: true
                text: backend.status
                wrapMode: Text.Wrap
                color: "#a7bbda"
                font.pixelSize: 12
            }
        }
    }

    Popup {
        id: details
        property var pkg: ({})
        anchors.centerIn: Overlay.overlay
        width: Math.min(window.width - 40, 560)
        height: 290
        modal: true
        focus: true
        padding: 24
        closePolicy: Popup.CloseOnEscape | Popup.CloseOnPressOutside
        background: Rectangle { radius: 17; color: "#223047"; border.color: "#435773" }
        ColumnLayout {
            anchors.fill: parent
            spacing: 14
            Label {
                text: details.pkg.name || ""
                font.pixelSize: 24
                font.bold: true
                color: "#ffffff"
            }
            Label {
                text: details.pkg.description || ""
                color: "#bfd0e7"
                wrapMode: Text.WordWrap
                Layout.fillWidth: true
            }
            Label {
                text: (details.pkg.source || "").toUpperCase() + "   " + (details.pkg.version || "")
                color: "#95b8f0"
                font.pixelSize: 13
            }
            Item { Layout.fillHeight: true }
            RowLayout {
                Layout.fillWidth: true
                Button { text: "Close"; onClicked: details.close() }
                Item { Layout.fillWidth: true }
                Button {
                    text: details.pkg.installed ? "Remove package" : "Install package"
                    highlighted: true
                    enabled: !backend.busy && (!details.pkg.installed || details.pkg.source !== "nix" || details.pkg.removeKey)
                    onClicked: {
                        backend.change(details.pkg.name, details.pkg.source,
                                       details.pkg.installed ? "remove" : "install",
                                       details.pkg.removeKey || "")
                        details.close()
                    }
                }
            }
        }
    }
}
