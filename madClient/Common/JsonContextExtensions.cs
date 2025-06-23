using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;
using System.Threading.Tasks;

namespace madClient.Common;

public static class JsonContextExtensions
{
    public static JsonTypeInfo<T> GetTypeInfo<T>(this JsonSerializerContext ctx)
    {
        var ti = ctx.GetType().GetProperty(typeof(T).Name)?.GetValue(ctx);
        if (ti is JsonTypeInfo<T> casted)
            return casted;

        throw new InvalidOperationException($"Type {typeof(T)} not registered in {ctx.GetType().Name}");
    }
}
