using System.ComponentModel.DataAnnotations;

namespace API.DTOs
{
    public class LoginDto
    {
        public string userName { get; set; }

        public string password { get; set; }
    }

}