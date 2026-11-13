using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace NpvTunnel.Core.Security;

public static class SafeJson
{
    public sealed class JsonTooLargeException : Exception
    {
        public JsonTooLargeException(string message)
            : base(message)
        {
        }
    }

    public sealed class JsonStructureException : Exception
    {
        public JsonStructureException(string message)
            : base(message)
        {
        }
    }

    public const int DefaultMaxBytes = 1048576;

    public const int DefaultMaxDepth = 32;

    public const int DefaultMaxStringLength = 8192;

    public const int DefaultMaxNodes = 20000;

    private static readonly JsonDocumentOptions Options = new JsonDocumentOptions
    {
        MaxDepth = 32,
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow
    };

    public static JsonDocument Parse(string text)
    {
        return Parse(text, 1048576);
    }

    public static JsonDocument Parse(string text, int maxBytes)
    {
        ArgumentNullException.ThrowIfNull(text, "text");
        int byteCount = Encoding.UTF8.GetByteCount(text);
        if (byteCount > maxBytes)
        {
            throw new JsonTooLargeException($"Configuration is {byteCount} bytes, the limit is {maxBytes} bytes.");
        }
        JsonDocument jsonDocument = JsonDocument.Parse(text, Options);
        Validate(jsonDocument.RootElement);
        return jsonDocument;
    }

    public static void Validate(JsonElement root)
    {
        int num = 0;
        Stack<JsonElement> stack = new Stack<JsonElement>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            JsonElement jsonElement = stack.Pop();
            if (++num > 20000)
            {
                throw new JsonStructureException($"Configuration has more than {20000} nodes.");
            }
            switch (jsonElement.ValueKind)
            {
            case JsonValueKind.String:
            {
                string @string = jsonElement.GetString();
                if (@string != null && @string.Length > 8192)
                {
                    throw new JsonStructureException($"A string field is {@string.Length} characters long, the limit is {8192}.");
                }
                break;
            }
            case JsonValueKind.Object:
            {
                HashSet<string> hashSet = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty item in jsonElement.EnumerateObject())
                {
                    if (item.Name.Length > 256)
                    {
                        throw new JsonStructureException("A property name is longer than 256 characters.");
                    }
                    if (!hashSet.Add(item.Name))
                    {
                        throw new JsonStructureException("Duplicate property '" + item.Name + "'.");
                    }
                    stack.Push(item.Value);
                }
                break;
            }
            case JsonValueKind.Array:
                foreach (JsonElement item2 in jsonElement.EnumerateArray())
                {
                    stack.Push(item2);
                }
                break;
            }
        }
    }
}
