using Amazix.Models;
using Amazix.Tests.Mocks;
using AmazixWeb.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Amazix.Tests.Controllers
{
    public class RegistrationControllerTest
    {
        [Fact]
        public async void Register_ReturnsOk_FValidUser()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(IdentityResult.Success);
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            var mockEmailService = RepositoryMocks.GetEmailServiceMock();
            var mockUrlHelper = RepositoryMocks.GetUrlHelperMock();
            var mockHttpContext = new Mock<HttpContext>();
            mockHttpContext.SetupGet(ctx => ctx.Request.Scheme).Returns("https");
            var registrationController = new RegistrationController(mockUserManager.Object, mockEmailService.Object);
            registrationController.Url = mockUrlHelper.Object;
            registrationController.ControllerContext = new ControllerContext { HttpContext = mockHttpContext.Object };


            // Act
            var result = await registrationController.Register(mockUserDto);

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
            mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Duplicate email." }));
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            var mockEmailService = RepositoryMocks.GetEmailServiceMock();
            var registrationController = new RegistrationController(mockUserManager.Object, mockEmailService.Object);

            // Act
            var result = await registrationController.Register(mockUserDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
        }

        [Fact]
        public async void Register_ReturnsBadRequest_ForUnvalidPassword()
        {
            // Arrange
            var mockUserManager = RepositoryMocks.GetUserManagerMock();
            mockUserManager.Setup(x => x.CreateAsync(It.IsAny<AppUser>(), It.IsAny<string>()))
                           .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Weak password." }));
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            var mockEmailService = RepositoryMocks.GetEmailServiceMock();
            var registrationController = new RegistrationController(mockUserManager.Object, mockEmailService.Object);

            // Act
            var result = await registrationController.Register(mockUserDto);

            // Assert
            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
        }
    }
}
