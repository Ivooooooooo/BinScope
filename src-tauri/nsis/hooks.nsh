; BinScope Explorer integration cleanup.
;
; Removes only the per-user verb that BinScope itself created, and only when
; the ownership marker matches. The shared `*` / `shell` branches and entries
; registered by other programs are never deleted.

!macro NSIS_HOOK_POSTUNINSTALL
  Push $0
  ReadRegStr $0 HKCU "Software\Classes\*\shell\BinScope.Analyze" "BinScopeOwner"
  StrCmp $0 "BinScope" 0 binscope_ctxmenu_done
    DeleteRegKey HKCU "Software\Classes\*\shell\BinScope.Analyze"
  binscope_ctxmenu_done:
  Pop $0
!macroend
