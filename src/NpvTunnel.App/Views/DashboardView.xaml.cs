using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using NpvTunnel.App.ViewModels;

namespace NpvTunnel.App.Views;

public partial class DashboardView : UserControl
{
    private MainViewModel? _vm;

    public DashboardView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
        Unloaded += (_, _) => Detach();
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        Detach();
        _vm = e.NewValue as MainViewModel;
        if (_vm is null)
        {
            return;
        }

        _vm.PropertyChanged += OnViewModelChanged;
        Apply();
    }

    private void Detach()
    {
        if (_vm is not null)
        {
            _vm.PropertyChanged -= OnViewModelChanged;
            _vm = null;
        }
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.State) or nameof(MainViewModel.StatusBracket))
        {
            Apply();
        }
    }

    /// <summary>Mirrors the phone: outlined ring when idle, filled glow when connected.</summary>
    private void Apply()
    {
        if (_vm is null)
        {
            return;
        }

        bool connected = _vm.IsConnected;
        bool busy = _vm.IsTransitioning;

        Ring.Stroke = connected
            ? (Brush)FindResource("Accent")
            : busy
                ? (Brush)FindResource("Amber")
                : (Brush)FindResource("StrokeBright");
        Ring.StrokeThickness = connected ? 2.2 : 1.6;

        Halo.Opacity = connected ? 1 : 0;
        PowerGlyph.Stroke = connected
            ? (Brush)FindResource("Accent")
            : busy
                ? (Brush)FindResource("Amber")
                : (Brush)FindResource("Accent");

        Bracket.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(_vm.StatusAccent));
    }

    private void OnDialClick(object sender, MouseButtonEventArgs e)
    {
        if (_vm?.ConnectCommand.CanExecute(null) == true)
        {
            _vm.ConnectCommand.Execute(null);
        }
    }
}
