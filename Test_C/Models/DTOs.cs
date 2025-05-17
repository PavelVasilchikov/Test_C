namespace Test_C.Models
{
    public class DTOs
    {
        public class CreateUserDto
        {
            public string Login { get; set; }
            public string Password { get; set; }
            public string Name { get; set; }
            public int Gender { get; set; } 
            public DateTime? Birthday { get; set; }
            public bool Admin { get; set; }
        }

        public class UpdateDetailsDto
        {
            public string Name { get; set; }
            public int Gender { get; set; } 
            public DateTime? Birthday { get; set; }
        }

        public class UpdatePasswordDto
        {
            public string OldPassword { get; set; }
            public string NewPassword { get; set; }
        }

        public class UpdateLoginDto
        {
            public string NewLogin { get; set; }
        }

        public class LoginDto
        {
            public string Username { get; set; }
            public string Password { get; set; }
        }
    }
}
