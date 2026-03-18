"""PacketSpy — Windows packet sniffer with per-application tracking."""

import ctypes
import os
import sys


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def _init_npcap():
    """Add Npcap DLLs to the search path BEFORE any Scapy imports.

    Scapy's pcap provider detection runs during `import scapy.all` and looks
    for wpcap.dll. Npcap installs to System32\\Npcap (not System32 directly),
    so we need to tell Windows where to find it.
    """
    npcap_path = os.path.join(os.environ.get("WINDIR", r"C:\Windows"),
                              "System32", "Npcap")
    if not os.path.exists(os.path.join(npcap_path, "wpcap.dll")):
        print("=" * 50)
        print("  ERROR: Npcap is not installed!")
        print("  Download from: https://npcap.com/#download")
        print("  Enable 'WinPcap API-compatible Mode' during install")
        print("=" * 50)
        input("Press Enter to exit...")
        sys.exit(1)

    # Add Npcap to DLL search path so ctypes.cdll.LoadLibrary finds wpcap.dll
    os.environ["PATH"] = npcap_path + os.pathsep + os.environ.get("PATH", "")
    try:
        ctypes.windll.kernel32.SetDllDirectoryW(npcap_path)
    except Exception:
        pass

    print(f"[PacketSpy] Npcap found at {npcap_path}")


def main():
    if not is_admin():
        print("ERROR: PacketSpy requires administrator privileges for Npcap access.")
        print("Please run this script as Administrator.")
        sys.exit(1)

    # CRITICAL: Must set up Npcap DLL path BEFORE any Scapy import
    _init_npcap()

    from scapy.config import conf
    conf.use_npcap = True

    # Now import scapy.all (and everything that depends on it)
    from packetspy.capture import CaptureEngine
    from packetspy.process_mapper import ProcessMapper
    from packetspy.web import create_app

    # Discover addons before creating the app
    from packetspy.addon_loader import discover_addons
    discover_addons()

    engine = CaptureEngine()
    mapper = ProcessMapper(refresh_interval=2.0)
    engine.process_mapper = mapper

    app = create_app(engine, mapper, profiles_dir="profiles")

    print("=" * 50)
    print("  PacketSpy v0.1.0")
    print("  http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop")
    print("=" * 50)

    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)


if __name__ == "__main__":
    main()
