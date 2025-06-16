using System.Collections.Concurrent;

namespace microauthd.Common;

public static class RateLimiter
{
    private static readonly int MaxEntries = 1000;

    private static readonly Dictionary<(string ip, string tag), Queue<DateTime>> _requests = new();
    private static readonly Dictionary<(string ip, string tag), DateTime> _lastSeen = new();
    private static readonly object _lock = new();

    private static readonly Dictionary<string, (int limit, TimeSpan window)> _limits = new()
    {
        ["auth"] = (20, TimeSpan.FromMinutes(1)),
        ["admin"] = (180, TimeSpan.FromMinutes(1))
    };

    public static bool IsAllowed(string ip, string tag)
    {
        var now = DateTime.UtcNow;
        var key = (ip, tag);

        lock (_lock)
        {
            if (!_limits.TryGetValue(tag, out var policy))
                policy = (20, TimeSpan.FromMinutes(1)); // default fallback

            if (!_requests.TryGetValue(key, out var queue))
            {
                if (_requests.Count >= MaxEntries)
                    PruneLeastRecentlyUsed();

                queue = new Queue<DateTime>();
                _requests[key] = queue;
            }

            while (queue.Count > 0 && (now - queue.Peek()) > policy.window)
                queue.Dequeue();

            if (queue.Count >= policy.limit)
                return false;

            queue.Enqueue(now);
            _lastSeen[key] = now;

            return true;
        }
    }

    private static void PruneLeastRecentlyUsed()
    {
        if (_lastSeen.Count == 0)
            return;

        var oldest = _lastSeen.OrderBy(x => x.Value).First().Key;
        _requests.Remove(oldest);
        _lastSeen.Remove(oldest);
    }
}

