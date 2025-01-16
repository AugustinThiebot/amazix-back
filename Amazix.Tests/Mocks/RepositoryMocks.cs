using Amazix.Email.Interfaces;
using Amazix.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Moq;

namespace Amazix.Tests.Mocks
{
    public class RepositoryMocks
    {
        public static Mock<UserManager<AppUser>> GetUserManagerMock()
        {
            var userStoreMock = new Mock<IUserStore<AppUser>>();
            var userManagerMock = new Mock<UserManager<AppUser>>(userStoreMock.Object, null, null, null, null, null, null, null, null);
            return userManagerMock;
        }

        public static Mock<IConfiguration> GetConfigurationMock()
        {
            var mockConfiguration = new Mock<IConfiguration>();
            mockConfiguration.Setup(c => c["Jwt:Key"]).Returns("a1-2fGb,8e4M@L?dfqesUu4TOS#32T_@");
            mockConfiguration.Setup(c => c["Jwt:Issuer"]).Returns("localhost:7139");
            mockConfiguration.Setup(c => c["Jwt:Audience"]).Returns("localhost:4200");
            mockConfiguration.Setup(c => c["Jwt:Name"]).Returns("auth_token");
            mockConfiguration.Setup(c => c["Jwt:RefreshName"]).Returns("auth_refresh_token");
            mockConfiguration.Setup(c => c["Jwt:TokenLifetimeMinutes"]).Returns("3");
            mockConfiguration.Setup(c => c["Jwt:RefreshTokenLifetimeHours"]).Returns("4");
            return mockConfiguration;
        }
        public static Mock<IEmailService> GetEmailServiceMock()
        {
            var mockEmailService = new Mock<IEmailService>();
            return mockEmailService;
        }
        public static UserForLoginDto GetUserForLoginDtoMock()
        {
            var mockUserDto = new UserForLoginDto
            {
                Email = "test@mail.com",
                Password = "TisIs@TestPassword1"
            };
            return mockUserDto;
        }
        public static UserForRegistrationDto GetUserForRegistrationDtoMock()
        {
            var mockUserDto = new UserForRegistrationDto
            {
                Email = "test@mail.com",
                Password = "TisIs@TestPassword1"
            };
            return mockUserDto;
        }
        public static LoggedUserDto GetLoginResponseDtoMock()
        {
            var mockUserDto = new LoggedUserDto
            {
                userGuid = "abcd",
                email = "test@mail.com"
            };
            return mockUserDto;
        }
        public static AppUser GetAppUserMock()
        {
            var mockAppUser = new AppUser
            {
                Id = "abcd",
                Email = "test@mail.com",
                UserName = "test@mail.com"
            };
            return mockAppUser;
        }

        public static Mock<IUrlHelper> GetUrlHelperMock()
        {
            var mockUrlHelper = new Mock<IUrlHelper>();
            mockUrlHelper.Setup(url => url.Action(It.IsAny<UrlActionContext>())).Returns("http://mockurl/ConfirmEmail");
            return mockUrlHelper;
        }
    }
}
