namespace Commerce.Models
{
    public class LoginResponseDto
    {
        public string token { get; set; }
        public UserInfoDto user { get; set; }
    }

    public class UserInfoDto
    {
        public string userGuid { get; set; }
        public string email { get; set; }
    }
}
