using Commerce.Models;
using Commerce.Tests.Mocks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Moq;

namespace Commerce.Tests.Controllers
{
    public class AuthenticationControllerTest
    {
        [Fact]
        public async void UserWithNoDigitPassword_CantSignUp()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock<AppUser>();
            var mockUserDto = new UserForRegistrationDto
            {
                Email = "test@mail.com",
                Password = "ThisIs@TestPassword"
            };
            AuthController authenticationController = new AuthController(mockUserManager.Object);

            // Act
            var result = await authenticationController.Register(mockUserDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            var errors = Assert.IsAssignableFrom<IEnumerable<IdentityError>>(badRequestResult.Value);
            Assert.Contains(errors, e => e.Description == "Password must contain at least one digit.");
        }
    }
}
