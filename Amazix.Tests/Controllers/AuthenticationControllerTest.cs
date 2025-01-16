using Amazix.Models;
using Amazix.Tests.Mocks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Amazix.Tests.Controllers
{
    public class AuthenticationControllerTest
    {
        [Fact]
        public async void Register_ReturnsOk_FValidUser()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(IdentityResult.Success);
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authenticationController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object);

            // Act
            var result = await authenticationController.Register(mockUserDto);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            string okResultValue = JsonConvert.SerializeObject((dynamic)okResult.Value);
            var jsonObject = JsonConvert.DeserializeObject<Dictionary<string, string>>(okResultValue);
            Assert.Equal("User registered successfully.", jsonObject["message"]);
        }

        [Fact]
        public async void Register_ReturnsBadRequest_ForDuplicateEmail()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Duplicate email." }));
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authenticationController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object);

            // Act
            var result = await authenticationController.Register(mockUserDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
        }

        [Fact]
        public async void Register_ReturnsBadRequest_ForUnvalidPassword()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Weak password." }));
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authenticationController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object);

            // Act
            var result = await authenticationController.Register(mockUserDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
        }

        [Fact]
        public async void Login_ReturnsUnauthorized_ForIncorrectPassword()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            var mockUserDto = RepositoryMocks.GetUserForLoginDtoMock();
            var mockAppUser = RepositoryMocks.GetAppUserMock();
            mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                           .ReturnsAsync(mockAppUser);
            mockUserManager.Setup(x => x.IsEmailConfirmedAsync(It.IsAny<AppUser>()))
                           .ReturnsAsync(true);
            mockUserManager.Setup(x => x.CheckPasswordAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(false);
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object);

            // Act
            var result = await authController.Login(mockUserDto);

            // Assert
            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Equal(401, unauthorizedResult.StatusCode);
            Assert.Equal("Invalid login attempt.", unauthorizedResult.Value);
        }

        [Fact]
        public async void Login_ReturnsUnauthorized_ForUnknownEmail()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            var mockUserDto = RepositoryMocks.GetUserForLoginDtoMock();
            mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                           .ReturnsAsync((AppUser)null);
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object);

            // Act
            var result = await authController.Login(mockUserDto);

            // Assert
            var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result);
            Assert.Equal(401, unauthorizedResult.StatusCode);
            Assert.Equal("Invalid login attempt.", unauthorizedResult.Value);

        }

        [Fact]
        public async void Login_ReturnsOkWithJwtToken_ForValid()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            mockConfiguration.SetupGet(c => c["Jwt:Key]"]).Returns("a1-2fGb,8e4M@L?dfqesUu4TOS#32T_@");
            mockConfiguration.SetupGet(c => c["Jwt:Issuer]"]).Returns("localhost:7139");
            mockConfiguration.SetupGet(c => c["Jwt:Audience]"]).Returns("localhost:4200");
            mockConfiguration.SetupGet(c => c["Jwt:Name]"]).Returns("auth_token");
            mockConfiguration.SetupGet(c => c["Jwt:TokenLifetimeMinutes]"]).Returns("3");
            var mockUserDto = RepositoryMocks.GetUserForLoginDtoMock();
            var mockAppUser = RepositoryMocks.GetAppUserMock();
            mockUserManager.Setup(x => x.FindByEmailAsync(It.IsAny<string>()))
                           .ReturnsAsync(mockAppUser);
            mockUserManager.Setup(x => x.IsEmailConfirmedAsync(It.IsAny<AppUser>()))
                           .ReturnsAsync(true);
            mockUserManager.Setup(x => x.CheckPasswordAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                            .ReturnsAsync(true);

            var mockHttpContext = new Mock<HttpContext>();
            var mockResponse = new Mock<HttpResponse>();
            var mockCookieResponse = new Mock<IResponseCookies>();
            mockHttpContext.Setup(x => x.Response).Returns(mockResponse.Object);
            mockResponse.Setup(x => x.Cookies).Returns(mockCookieResponse.Object);
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object)
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = mockHttpContext.Object
                }
            };

            // Act
            var result = await authController.Login(mockUserDto);

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);

            var responseBody = Assert.IsType<LoggedUserDto>(okResult.Value);
            Assert.NotNull(responseBody);
            Assert.Equal(responseBody.email, mockAppUser.Email);
            Assert.Equal(responseBody.userGuid, mockAppUser.Id);

            mockCookieResponse.Verify(c => c.Append("auth_token", It.IsAny<string>(), It.IsAny<CookieOptions>()), Times.Once);
        }

        [Fact]
        public void Logout_ReturnsOkandDeletesCookie()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            var mockConfiguration = RepositoryMocks.GetConfigurationMock();
            var mockHttpContext = new Mock<HttpContext>();
            var mockResponse = new Mock<HttpResponse>();
            var mockCookieResponse = new Mock<IResponseCookies>();
            mockHttpContext.Setup(x => x.Response).Returns(mockResponse.Object);
            mockResponse.Setup(x => x.Cookies).Returns(mockCookieResponse.Object);
            var mockEmailSender = RepositoryMocks.GetEmailSenderMock();
            var authController = new AuthController(mockUserManager.Object, mockConfiguration.Object, mockEmailSender.Object)
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = mockHttpContext.Object
                }
            };

            // Act
            var result = authController.Logout();

            // Assert
            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            mockCookieResponse.Verify(c => c.Delete(It.IsAny<string>()), Times.Exactly(2));

        }

    }
}
