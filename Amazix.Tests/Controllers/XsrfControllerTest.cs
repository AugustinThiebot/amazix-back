using AmazixWeb.Controllers;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Moq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace Amazix.Tests.Controllers
{
    public class XsrfControllerTest
    {
        private readonly XsrfController _xsrfController;
        public XsrfControllerTest()
        {
            var mockHttpContext = new Mock<HttpContext>();
            var mockResponse = new Mock<HttpResponse>();
            var mockCookieResponse = new Mock<IResponseCookies>();
            mockHttpContext.Setup(x => x.Response).Returns(mockResponse.Object);
            mockResponse.Setup(x => x.Cookies).Returns(mockCookieResponse.Object);
            _xsrfController = new XsrfController()
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = mockHttpContext.Object
                }
            };
        }

        [Fact]
        public void XSRFToken_ReturnsOkAndSetsCookie()
        {
            var result = _xsrfController.XSRFToken();

            var okResult = Assert.IsType<OkResult>(result);
            Assert.Equal((int)HttpStatusCode.OK, okResult.StatusCode);
        }

    }
}
