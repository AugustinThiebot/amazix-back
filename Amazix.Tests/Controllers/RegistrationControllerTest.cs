using Amazix.Models;
using Amazix.Tests.Mocks;
using AmazixWeb.Controllers;
using AmazixWeb.Services.Interfaces;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Newtonsoft.Json;

namespace Amazix.Tests.Controllers
{
    public class RegistrationControllerTest
    {
        [Fact]
        public async Task Register_ShouldReturnOk_WhenRegistrationSucceeds()
        {
            var mockRegistrationService = new Mock<IRegistrationService>();
            mockRegistrationService.Setup(s => s.RegisterUserAsync(It.IsAny<UserForRegistrationDto>()))
                                   .ReturnsAsync(IdentityResult.Success);
            var mockHttpContext = new Mock<HttpContext>();
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.Setup(r => r.Scheme).Returns("https");
            mockHttpContext.Setup(c => c.Request).Returns(mockRequest.Object);
            var registrationController = new RegistrationController(mockRegistrationService.Object);
            registrationController.ControllerContext = new ControllerContext
            {
                HttpContext = mockHttpContext.Object,
            };
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();

            var result = await registrationController.Register(mockUserDto);

            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            string okResultValue = JsonConvert.SerializeObject((dynamic)okResult.Value);
            var jsonObject = JsonConvert.DeserializeObject<Dictionary<string, string>>(okResultValue);
            Assert.Equal("User registered successfully.", jsonObject["message"]);
        }

        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenRegistrationFails()
        {
            var mockRegistrationService = new Mock<IRegistrationService>();
            mockRegistrationService.Setup(s => s.RegisterUserAsync(It.IsAny<UserForRegistrationDto>()))
                                   .ReturnsAsync(IdentityResult.Failed());
            var mockHttpContext = new Mock<HttpContext>();
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.Setup(r => r.Scheme).Returns("https");
            mockHttpContext.Setup(c => c.Request).Returns(mockRequest.Object);
            var registrationController = new RegistrationController(mockRegistrationService.Object);
            registrationController.ControllerContext = new ControllerContext
            {
                HttpContext = mockHttpContext.Object,
            };
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();

            var result = await registrationController.Register(mockUserDto);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
        }
    }
}
