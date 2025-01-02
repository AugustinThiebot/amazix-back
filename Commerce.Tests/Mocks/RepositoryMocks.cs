using Commerce.Models;
using Microsoft.AspNetCore.Identity;
using Moq;

namespace Commerce.Tests.Mocks
{
    public class RepositoryMocks
    {
        public static Mock<UserManager<AppUser>> GetUserManagerMock()
        {
            var userStoreMock = new Mock<IUserStore<AppUser>>();
            var userManagerMock = new Mock<UserManager<AppUser>>(userStoreMock.Object, null, null, null, null, null, null, null, null);
            return userManagerMock;
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
    }
}
