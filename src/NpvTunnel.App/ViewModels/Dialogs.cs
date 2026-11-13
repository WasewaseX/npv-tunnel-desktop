using System.Windows;
using NpvTunnel.App.Views;

namespace NpvTunnel.App.ViewModels;

/// <summary>Thin wrapper so view models never touch WPF dialog plumbing directly.</summary>
public static class Dialogs
{
    public static void Show(Window? owner, string title, string message, MessageBoxImage icon = MessageBoxImage.Information)
    {
        if (owner is null)
        {
            MessageBox.Show(message, title, MessageBoxButton.OK, icon);
            return;
        }

        MessageBox.Show(owner, message, title, MessageBoxButton.OK, icon);
    }

    /// <summary>Passphrase prompt for locked .npvt files. Returns null when cancelled.</summary>
    public static string? AskPassphrase(Window? owner, string prompt, bool allowEmpty = false)
    {
        var dialog = new PromptWindow(prompt, allowEmpty)
        {
            Owner = owner,
            WindowStartupLocation = owner is null
                ? WindowStartupLocation.CenterScreen
                : WindowStartupLocation.CenterOwner,
        };

        return dialog.ShowDialog() == true ? dialog.Value : null;
    }
}
