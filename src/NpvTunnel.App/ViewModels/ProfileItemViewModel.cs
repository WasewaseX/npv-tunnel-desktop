using System;
using NpvTunnel.App.Services;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;

namespace NpvTunnel.App.ViewModels;

public sealed class ProfileItemViewModel : ViewModelBase
{
    private long _pingMs;

    public Guid Id { get; }

    public NpvtDocument Document { get; }

    public string Name { get; }

    public string Address { get; }

    public int Port { get; }

    public string Protocol { get; }

    public string Security { get; }

    public string Sni { get; }

    public string Endpoint => $"{Address}:{Port}";

    public string Chip => Protocol + " · " + Security;

    public string Initial
    {
        get
        {
            if (Protocol.Length <= 0)
            {
                return "?";
            }
            return Protocol.Substring(0, 1);
        }
    }

    public long PingMs
    {
        get
        {
            return _pingMs;
        }
        private set
        {
            if (Set(ref _pingMs, value, "PingMs"))
            {
                OnPropertyChanged("PingText");
                OnPropertyChanged("PingGood");
            }
        }
    }

    public string PingText
    {
        get
        {
            if (PingMs > 0)
            {
                return $"{PingMs} ms";
            }
            return "—";
        }
    }

    public bool PingGood
    {
        get
        {
            long pingMs = PingMs;
            if (pingMs > 0)
            {
                return pingMs < 300;
            }
            return false;
        }
    }

    public ProfileItemViewModel(StoredProfile stored)
    {
        Id = stored.Id;
        Document = stored.Document;
        Name = stored.Document.Name ?? stored.Document.Address;
        Address = stored.Document.Address;
        Port = stored.Document.Port;
        Protocol = (stored.Document.Protocol ?? "vless").ToUpperInvariant();
        Security = (stored.Document.Security ?? "none").ToUpperInvariant();
        Sni = stored.Document.Sni ?? string.Empty;
        _pingMs = stored.LastPingMs;
    }

    public void SetPing(long milliseconds)
    {
        PingMs = milliseconds;
    }

    public static ProfileItemViewModel FromProfile(Profile profile)
    {
        return new ProfileItemViewModel(new StoredProfile
        {
            Id = profile.Id,
            Document = NpvtDocument.FromProfile(profile)
        });
    }
}
