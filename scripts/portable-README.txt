BinScope portable
=================

BinScope runs without installation. Keep this folder together and start
BinScope.exe. Do not copy the executable by itself: it needs rules\ and
databases\ next to it.

Requirements
------------
- Windows 10 or Windows 11, 64-bit.
- Microsoft Edge WebView2 Runtime. It is preinstalled on current Windows
  builds; if BinScope does not start, install the Evergreen WebView2 Runtime
  from Microsoft. No administrator rights are required to run BinScope.

Where data lives
----------------
Settings, imported rules, downloaded sources, analysis history and the WebView2
profile are stored per Windows user:

  %APPDATA%\com.binscope.analyzer
  %LOCALAPPDATA%\com.binscope.analyzer\webview2

Nothing is written into this folder. You can move the folder, rename it, put it
on another drive or run it from removable media. The marker file
"binscope.portable" must stay next to BinScope.exe.

Windows context menu
--------------------
Open Settings > Windows Integration and enable
"Analyze with BinScope". The entry is registered per user under
HKEY_CURRENT_USER and points at this folder's BinScope.exe, so it does not need
administrator rights and never runs the selected file.

Windows 10 shows it in the classic context menu. Windows 11 lists legacy
entries under "Show more options"; the first-level Windows 11 menu requires a
packaged shell extension, which BinScope does not install.

If you move the folder, BinScope detects the stale path on its next launch and
repairs the registration automatically. The enabled preference is stored per
user in the registry, not in this folder. You can also use
Settings > Windows Integration > Repair registration. Disabling the integration
removes every BinScope-owned registry entry.

Notes
-----
- Analysis is local. Samples are never uploaded automatically.
- The optional VirusTotal API key is stored in Windows Credential Manager.
- Bundled content: BinScope YARA rules, the DIE PE signature database and the
  built-in signature JSON.
- SHA256SUMS.txt in this folder contains the executable checksum.
