namespace madTypes.Common;

public class ApiResult<T>
{
    public bool Success { get; init; }
    public T? Value { get; init; }
    public string? Error { get; init; }
    public object? ErrorObject { get; init; }
    public int StatusCode { get; init; }

    public bool IsSuccess => StatusCode is >= 200 and < 300;

    public static ApiResult<T> Ok(T value, int status = 200)
        => new() { Success = true, Value = value, StatusCode = status };

    public static ApiResult<T> Fail(string error, int status = 400)
        => new() { Success = false, Error = error, StatusCode = status };

    public static ApiResult<T> FailObj(object errorObject, int status = 400)
        => new() { Success = false, ErrorObject = errorObject, StatusCode = status };

    public static ApiResult<T> Forbidden(string message = "Forbidden")
        => new() { Success = false, Error = message, StatusCode = 403 };

    public static ApiResult<T> NotFound(string message = "Not found")
        => new() { Success = false, Error = message, StatusCode = 404 };
}
