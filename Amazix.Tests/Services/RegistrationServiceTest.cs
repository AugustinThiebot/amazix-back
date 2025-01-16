using Amazix.Models;
using Amazix.Email.Interfaces;
using AmazixWeb.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using Amazix.Email;
using Microsoft.AspNetCore.Mvc.Routing;
using Amazix.Tests.Mocks;

namespace Amazix.Tests.Services
{
    public class RegistrationServiceTests
    {
        private readonly Mock<UserManager<AppUser>> _userManagerMock;
        private readonly Mock<IEmailService> _emailServiceMock;
        private readonly Mock<IUrlHelper> _urlHelperMock;
        private readonly Mock<IHttpContextAccessor> _httpContextAccessorMock;
        private readonly RegistrationService _registrationService;

        public RegistrationServiceTests()
        {
            _userManagerMock = new Mock<UserManager<AppUser>>(
                new Mock<IUserStore<AppUser>>().Object, null, null, null, null, null, null, null, null);

            _emailServiceMock = new Mock<IEmailService>();
            _urlHelperMock = new Mock<IUrlHelper>();
            _httpContextAccessorMock = new Mock<IHttpContextAccessor>();

            var httpContextMock = new Mock<HttpContext>();
            var requestMock = new Mock<HttpRequest>();
            requestMock.Setup(r => r.Scheme).Returns("https");
            httpContextMock.Setup(c => c.Request).Returns(requestMock.Object);
            _httpContextAccessorMock.Setup(c => c.HttpContext).Returns(httpContextMock.Object);

            _registrationService = new RegistrationService(
                _userManagerMock.Object,
                _emailServiceMock.Object,
                _urlHelperMock.Object,
                _httpContextAccessorMock.Object);
        }

        [Fact]
        public async Task RegisterUserAsync_ShouldReturnSuccess_WhenUserCreatedSuccessfully()
        {
            var userDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            _userManagerMock.Setup(um => um.CreateAsync(It.IsAny<AppUser>(), userDto.Password))
                .ReturnsAsync(IdentityResult.Success);
            _userManagerMock.Setup(um => um.GenerateEmailConfirmationTokenAsync(It.IsAny<AppUser>()))
                .ReturnsAsync("fake-token");
            _urlHelperMock.Setup(uh => uh.Action(It.IsAny<UrlActionContext>()))
                .Returns("https://example.com/confirm-email");

            var result = await _registrationService.RegisterUserAsync(userDto);

            Assert.True(result.Succeeded);
            _emailServiceMock.Verify(es => es.SendEmail(It.IsAny<Message>()), Times.Once);
        }


        [Fact]
        public async Task RegisterUserAsync_ShouldNotSendEmail_WhenUserCreationFails()
        {
            var userDto = RepositoryMocks.GetUserForRegistrationDtoMock();
            _userManagerMock.Setup(um => um.CreateAsync(It.IsAny<AppUser>(), userDto.Password))
                .ReturnsAsync(IdentityResult.Failed(new IdentityError { Description = "Error creating user." }));

            var result = await _registrationService.RegisterUserAsync(userDto);

            Assert.False(result.Succeeded);
            _emailServiceMock.Verify(es => es.SendEmail(It.IsAny<Message>()), Times.Never);
        }

        [Fact]
        public async Task ConfirmEmailAsync_ShouldReturnSuccess_WhenEmailConfirmed()
        {
            var userId = "user-id";
            var token = "valid-token";
            var user = new AppUser { Id = userId };

            _userManagerMock.Setup(um => um.FindByIdAsync(userId)).ReturnsAsync(user);
            _userManagerMock.Setup(um => um.ConfirmEmailAsync(user, token))
                .ReturnsAsync(IdentityResult.Success);

            var result = await _registrationService.ConfirmEmailAsync(userId, token);

            Assert.True(result.Succeeded);
        }

        [Fact]
        public async Task ConfirmEmailAsync_ShouldThrowException_WhenUserIdOrTokenIsInvalid()
        {
            string userId = null;
            var token = "valid-token";

            await Assert.ThrowsAsync<ArgumentException>(() => _registrationService.ConfirmEmailAsync(userId, token));
        }

        [Fact]
        public async Task ConfirmEmailAsync_ShouldThrowException_WhenUserNotFound()
        {
            var userId = "user-id";
            var token = "valid-token";
            _userManagerMock.Setup(um => um.FindByIdAsync(userId)).ReturnsAsync((AppUser)null);

            await Assert.ThrowsAsync<ArgumentException>(() => _registrationService.ConfirmEmailAsync(userId, token));
        }
    }
}
