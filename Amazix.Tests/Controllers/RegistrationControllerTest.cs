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
        private readonly Mock<IRegistrationService> _mockRegistrationService;
        private readonly RegistrationController _registrationController;
        public RegistrationControllerTest()
        {
            _mockRegistrationService = new Mock<IRegistrationService>();
            _registrationController = new RegistrationController(_mockRegistrationService.Object);
            var mockHttpContext = new Mock<HttpContext>();
            var mockRequest = new Mock<HttpRequest>();
            mockRequest.Setup(r => r.Scheme).Returns("https");
            mockHttpContext.Setup(c => c.Request).Returns(mockRequest.Object);
            _registrationController.ControllerContext = new ControllerContext
            {
                HttpContext = mockHttpContext.Object,
            };

        }
        [Fact]
        public async Task Register_ShouldReturnOk_WhenRegistrationSucceeds()
        {
            _mockRegistrationService.Setup(s => s.RegisterUserAsync(It.IsAny<UserForRegistrationDto>()))
                                   .ReturnsAsync(IdentityResult.Success);
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();

            var result = await _registrationController.Register(mockUserDto);

            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            string okResultValue = JsonConvert.SerializeObject((dynamic)okResult.Value);
            var jsonObject = JsonConvert.DeserializeObject<Dictionary<string, string>>(okResultValue);
            Assert.Equal("User registered successfully.", jsonObject["message"]);
        }

        [Fact]
        public async Task Register_ShouldReturnBadRequest_WhenRegistrationFails()
        {
            _mockRegistrationService.Setup(s => s.RegisterUserAsync(It.IsAny<UserForRegistrationDto>()))
                                   .ReturnsAsync(IdentityResult.Failed());
            
            var mockUserDto = RepositoryMocks.GetUserForRegistrationDtoMock();

            var result = await _registrationController.Register(mockUserDto);

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
        }

        [Fact]
        public async Task ConfirmEmail_ShouldReturnOk_WhenConfirmationSucceeds()
        {
            _mockRegistrationService.Setup(s => s.ConfirmEmailAsync(It.IsAny<string>(), It.IsAny<string>()))
                                    .ReturnsAsync(IdentityResult.Success);

            var result = await _registrationController.ConfirmEmail("anyUserId", "anyToken");

            var okResult = Assert.IsType<OkObjectResult>(result);
            Assert.Equal(200, okResult.StatusCode);
            string okResultValue = (dynamic)okResult.Value;
            Assert.Equal("Email confirmed successfully.", okResultValue);
        }

        [Fact]
        public async Task ConfirmEmail_ShouldReturnBadRequest_WhenConfirmationFails()
        {
            _mockRegistrationService.Setup(s => s.ConfirmEmailAsync(It.IsAny<string>(), It.IsAny<string>()))
                                    .ReturnsAsync(IdentityResult.Failed());

            var result = await _registrationController.ConfirmEmail("anyUserId", "anyToken");

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
            string badRequestResultValue = JsonConvert.SerializeObject((dynamic)badRequestResult.Value);
            var jsonObject = JsonConvert.DeserializeObject<Dictionary<string, string>>(badRequestResultValue);
            Assert.Equal("Email confirmation failed.", jsonObject["message"]);
        }

        [Fact]
        public async Task ConfirmEmail_ShouldReturnBadRequest_WhenExcepionIsThrown()
        {
            _mockRegistrationService.Setup(s => s.ConfirmEmailAsync(It.IsAny<string>(), It.IsAny<string>()))
                                    .ThrowsAsync(new Exception("Test Exception"));

            var result = await _registrationController.ConfirmEmail("anyUserId", "anyToken");

            var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Equal(400, badRequestResult.StatusCode);
            Assert.Contains("Test Exception\r\n", badRequestResult.Value.ToString());
        }
    }
}
