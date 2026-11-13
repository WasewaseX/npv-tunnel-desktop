using System.Windows.Controls;
using NpvTunnel.App.Services;

namespace NpvTunnel.App.Views;

public partial class LogsView : UserControl
{
    public LogsView()
    {
        InitializeComponent();

        Loaded += (_, _) =>
        {
            App.Logs.EntryAdded += OnEntryAdded;
            ScrollToEnd();
        };

        Unloaded += (_, _) => App.Logs.EntryAdded -= OnEntryAdded;
    }

    private void OnEntryAdded(object? sender, LogEntry entry)
    {
        if (FollowToggle.IsChecked == true)
        {
            Dispatcher.BeginInvoke(ScrollToEnd);
        }
    }

    private void ScrollToEnd()
    {
        if (LogList.Items.Count > 0)
        {
            LogList.ScrollIntoView(LogList.Items[^1]);
        }
    }
}
