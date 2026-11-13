using System.Windows;
using System.Windows.Controls;
using NpvTunnel.App.ViewModels;

namespace NpvTunnel.App.Views;

public partial class ServersView : UserControl
{
    public ServersView()
    {
        InitializeComponent();

        DataContextChanged += (_, e) =>
        {
            if (e.OldValue is MainViewModel oldVm)
            {
                oldVm.SearchFocusRequested -= OnSearchFocusRequested;
            }

            if (e.NewValue is MainViewModel newVm)
            {
                newVm.SearchFocusRequested += OnSearchFocusRequested;
            }
        };
    }

    private void OnSearchFocusRequested(object? sender, System.EventArgs e)
    {
        SearchBox.Focus();
        SearchBox.SelectAll();
    }
}
