import ctypes
from pathlib import Path


def local_volume(path: Path) -> bool:
    return ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 3  # type: ignore[attr-defined]


def is_owner(path: Path) -> bool:
    import win32security

    security = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION
    )
    return bool(current_sid() == security.GetSecurityDescriptorOwner())


def current_sid():
    import win32api
    import win32con
    import win32security

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        user, _ = win32security.GetTokenInformation(token, win32security.TokenUser)
        return user
    finally:
        token.Close()


def security_snapshot(path: Path) -> str:
    import win32security as security

    descriptor = security.GetNamedSecurityInfo(
        str(path), security.SE_FILE_OBJECT, security.DACL_SECURITY_INFORMATION
    )
    return str(
        security.ConvertSecurityDescriptorToStringSecurityDescriptor(
            descriptor, security.SDDL_REVISION_1, security.DACL_SECURITY_INFORMATION
        )
    )


def set_private(path: Path, *, directory: bool = False) -> None:
    import ntsecuritycon
    import win32security as security

    acl = security.ACL()
    flags = 3 if directory else 0  # inherit into files and directories
    for sid in (current_sid(), security.CreateWellKnownSid(security.WinLocalSystemSid, None)):
        acl.AddAccessAllowedAceEx(security.ACL_REVISION, flags, ntsecuritycon.FILE_ALL_ACCESS, sid)
    security.SetNamedSecurityInfo(
        str(path),
        security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        acl,
        None,
    )


def restore_security(path: Path, snapshot: str) -> None:
    import win32security as security

    descriptor = security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        snapshot,
        security.SDDL_REVISION_1,
    )
    control, _ = descriptor.GetSecurityDescriptorControl()
    protection = (
        security.PROTECTED_DACL_SECURITY_INFORMATION
        if control & 0x1000
        else security.UNPROTECTED_DACL_SECURITY_INFORMATION
    )
    security.SetNamedSecurityInfo(
        str(path),
        security.SE_FILE_OBJECT,
        security.DACL_SECURITY_INFORMATION | protection,
        None,
        None,
        descriptor.GetSecurityDescriptorDacl(),
        None,
    )
