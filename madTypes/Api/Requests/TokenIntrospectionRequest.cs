using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace madTypes.Api.Requests
{
    public class TokenIntrospectionRequest
    {
        public string Token { get; set; } = string.Empty;
    }
}
