using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using NpvTunnel.App.ViewModels;

namespace NpvTunnel.App.Views;

public partial class ServersView : UserControl
{
    private MainViewModel? _vm;

    public ServersView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (_vm is not null)
        {
            _vm.SearchFocusRequested -= OnSearchFocusRequested;
        }

        _vm = e.NewValue as MainViewModel;
        if (_vm is not null)
        {
            _vm.SearchFocusRequested += OnSearchFocusRequested;
        }
    }

    private void OnSearchFocusRequested(object? sender, System.EventArgs e)
    {
        Dispatcher.BeginInvoke(() =>
        {
            SearchBox.Focus();
            SearchBox.SelectAll();
        });
    }

    private void OnSmartRouteClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is Button)
        {
            return;
        }

        _vm?.ConnectCommand.Execute(null);
    }

    private void OnProfileRowClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is Button)
        {
            return;
        }

        if (sender is FrameworkElement { DataContext: ProfileItemViewModel item })
        {
            _vm?.SelectProfileCommand.Execute(item);
        }
    }
}
