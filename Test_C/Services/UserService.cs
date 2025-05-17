using Test_C.Models;

namespace Test_C.Services
{
    public class UserService
    {
        private readonly List<User> _users;

        public UserService()
        {
            _users = new List<User>();
            InitializeAdmin();
        }

        private void InitializeAdmin()
        {
            if (!_users.Any(u => u.Login == "admin"))
            {
                _users.Add(new User
                {
                    Guid = Guid.NewGuid(),
                    Login = "admin",
                    Password = "admin", 
                    Name = "Administrator",
                    Gender = 1,
                    Birthday = null,
                    Admin = true,
                    CreatedOn = DateTime.UtcNow,
                    CreatedBy = "system"
                });
            }
        }

        public List<User> GetUsers() => _users;
    }
}
