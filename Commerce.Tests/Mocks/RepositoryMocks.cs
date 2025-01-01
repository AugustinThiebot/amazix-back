using Commerce.Models;
using Microsoft.AspNetCore.Identity;
using Moq;

namespace Commerce.Tests.Mocks
{
    public class RepositoryMocks
    {
        public static Mock<UserManager<TUser>> GetUserManagerMock<TUser>() where TUser : class
        {
            var userManagerMock = new Mock<UserManager<TUser>>(Mock.Of<IUserStore<TUser>>(), null, null, null, null, null, null, null, null);
            userManagerMock.Setup(um => um.CreateAsync(It.IsAny<TUser>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Failed(new IdentityError
            {
                Code = "Password is TooWeak",
                Description = "Password must contain at least one digit."
            }));

            return userManagerMock;
        }
    }
}
