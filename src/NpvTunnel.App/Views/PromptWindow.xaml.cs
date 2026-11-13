using System.Windows;
using System.Windows.Input;

namespace NpvTunnel.App.Views;

public partial class PromptWindow : Window
{
    private readonly bool _allowEmpty;

    public PromptWindow(string prompt, bool allowEmpty)
    {
        InitializeComponent();
        _allowEmpty = allowEmpty;
        PromptText.Text = prompt;
        Loaded += (_, _) => PassphraseBox.Focus();
    }

    public string Value { get; private set; } = string.Empty;

    private void OnAccept(object sender, RoutedEventArgs e)
    {
        if (!_allowEmpty && PassphraseBox.Password.Length == 0)
        {
            PromptText.Text = "A passphrase is required for this file.";
            return;
        }

        Value = PassphraseBox.Password;
        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        Value = string.Empty;
        DialogResult = false;
        Close();
    }

    private void OnDrag(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
        {
            DragMove();
        }
    }
}
