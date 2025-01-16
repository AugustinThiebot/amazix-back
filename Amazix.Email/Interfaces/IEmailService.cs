using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Amazix.Email.Interfaces
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
