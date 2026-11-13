namespace NpvTunnel.Core.Import;

public enum ImportError
{
    None,
    Empty,
    UnknownFormat,
    MalformedUri,
    MissingCredential,
    UnsupportedProtocol,
    TooLarge,
    EncryptedNeedsPassword,
    BadPassword,
    LegacyEncryptedConfig,
    InvalidField
}
