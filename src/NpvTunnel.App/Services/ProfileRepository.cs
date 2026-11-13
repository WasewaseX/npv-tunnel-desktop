using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using NpvTunnel.Core.Import;
using NpvTunnel.Core.Models;

namespace NpvTunnel.App.Services;

public sealed class ProfileRepository
{
    private readonly LogService _log;

    private readonly List<StoredProfile> _items = new List<StoredProfile>();

    private static readonly JsonSerializerOptions Options = new JsonSerializerOptions
    {
        WriteIndented = false
    };

    public IReadOnlyList<StoredProfile> Items => _items;

    public event EventHandler? Changed;

    public ProfileRepository(LogService log)
    {
        _log = log;
        Load();
    }

    public Profile? GetProfile(Guid id)
    {
        StoredProfile? storedProfile = _items.FirstOrDefault((StoredProfile p) => p.Id == id);
        Profile? profile = storedProfile?.Document.ToProfile();
        if (profile == null)
        {
            return null;
        }
        return WithMetadata(profile, storedProfile!);
    }

    public StoredProfile? Find(Guid id)
    {
        return _items.FirstOrDefault((StoredProfile p) => p.Id == id);
    }

    public StoredProfile Add(Profile profile)
    {
        StoredProfile storedProfile = new StoredProfile
        {
            Id = profile.Id,
            Document = NpvtDocument.FromProfile(profile)
        };
        _items.Add(storedProfile);
        Save();
        _log.Info("profiles", $"Added profile '{profile.Name}' ({profile.Protocol} {profile.Endpoint}).");
        return storedProfile;
    }

    public void Remove(Guid id)
    {
        StoredProfile? storedProfile = _items.FirstOrDefault((StoredProfile p) => p.Id == id);
        if (storedProfile != null)
        {
            _items.Remove(storedProfile);
            Save();
            _log.Info("profiles", "Removed profile '" + storedProfile.Document.Name + "'.");
        }
    }

    public void UpdatePing(Guid id, long milliseconds)
    {
        StoredProfile? storedProfile = _items.FirstOrDefault((StoredProfile p) => p.Id == id);
        if (storedProfile != null)
        {
            storedProfile.LastPingMs = milliseconds;
            Save();
        }
    }

    public void MarkConnected(Guid id)
    {
        StoredProfile? storedProfile = _items.FirstOrDefault((StoredProfile p) => p.Id == id);
        if (storedProfile != null)
        {
            storedProfile.LastConnectedAt = DateTimeOffset.Now;
            Save();
        }
    }

    private static Profile WithMetadata(Profile profile, StoredProfile stored)
    {
        profile.Id = stored.Id;
        profile.ImportedAt = stored.ImportedAt;
        return profile;
    }

    private void Load()
    {
        string? text = SecretStore.LoadEncrypted(AppPaths.ProfilesFile);
        if (string.IsNullOrWhiteSpace(text))
        {
            return;
        }
        try
        {
            List<StoredProfile>? list = JsonSerializer.Deserialize<List<StoredProfile>>(text, Options);
            if (list != null)
            {
                _items.AddRange(list);
            }
        }
        catch (JsonException ex)
        {
            _log.Error("profiles", "The profile store could not be read and was left untouched: " + ex.Message);
        }
    }

    private void Save()
    {
        try
        {
            SecretStore.SaveEncrypted(AppPaths.ProfilesFile, JsonSerializer.Serialize(_items, Options));
            this.Changed?.Invoke(this, EventArgs.Empty);
        }
        catch (Exception ex) when (((ex is IOException || ex is UnauthorizedAccessException) ? 1 : 0) != 0)
        {
            _log.Error("profiles", "Could not save the profile store: " + ex.Message);
        }
    }
}
