using System.Web.Http;

namespace OAuth.Controllers
{
    [Authorize]
    public class MeController : ApiController
    {
        public string Get()
        {
            return this.User.Identity.Name;
        }
    }
}
