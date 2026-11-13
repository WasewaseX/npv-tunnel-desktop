using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace NpvTunnel.App.Services;

/// <summary>
/// Keeps the runtime directory, the settings file and the profile store readable by
/// this account only. The Windows equivalent of chmod 600: inheritance is switched off
/// and a single full-control entry for the current user is written.
/// </summary>
public static class WindowsAcl
{
    public static bool RestrictToCurrentUser(string path)
    {
        try
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            SecurityIdentifier sid = identity.User!;

            if (Directory.Exists(path))
            {
                var info = new DirectoryInfo(path);
                DirectorySecurity security = info.GetAccessControl();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(
                    sid, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                info.SetAccessControl(security);
                return true;
            }

            if (File.Exists(path))
            {
                var info = new FileInfo(path);
                FileSecurity security = info.GetAccessControl();
                security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                security.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl, AccessControlType.Allow));
                info.SetAccessControl(security);
                return true;
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or PlatformNotSupportedException or InvalidOperationException)
        {
            // A filesystem without ACLs (FAT32, some network shares): the file still
            // lives under the user's own profile, so this is a reduction in hardening,
            // not an exposure on its own.
        }

        return false;
    }
}
