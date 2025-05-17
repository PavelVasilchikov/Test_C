using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Test_C.Models;
using Test_C.Services;

namespace Test_C.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserService _userService;

        public UsersController(UserService userService)
        {
            _userService = userService;
        }

        [Authorize]
        [HttpPost("create-users")]
        public IActionResult CreateUsers([FromBody] List<DTOs.CreateUserDto> dtos)
        {
            var currentLogin = User.Identity?.Name;

            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);
            if (currentUser == null || !currentUser.Admin)
                return StatusCode(403, "Только администратор может создавать новых пользователей");

            if (dtos == null || !dtos.Any())
                return BadRequest("Не переданы данные пользователей");

            foreach (var dto in dtos)
            {
                if (!IsValidLogin(dto.Login) || !IsValidPassword(dto.Password))
                    return BadRequest($"Логин или пароль недопустимы для пользователя {dto.Login}. Допускаются только латинские буквы и цифры.");

                if (_userService.GetUsers().Any(u => u.Login == dto.Login && !u.RevokedOn.HasValue))
                    return Conflict($"Пользователь с логином {dto.Login} уже существует.");
            }

            var newUsers = new List<User>();
            var createdGuids = new List<Guid>();

            foreach (var dto in dtos)
            {
                var newUser = new User
                {
                    Guid = Guid.NewGuid(),
                    Login = dto.Login,
                    Password = dto.Password,
                    Name = dto.Name,
                    Gender = dto.Gender,
                    Birthday = dto.Birthday,
                    Admin = dto.Admin,
                    CreatedOn = DateTime.UtcNow,
                    CreatedBy = currentLogin,
                    ModifiedOn = DateTime.UtcNow,
                    ModifiedBy = currentLogin,
                    RevokedOn = null,
                    RevokedBy = null
                };

                newUsers.Add(newUser);
                createdGuids.Add(newUser.Guid);
            }

            _userService.GetUsers().AddRange(newUsers);

            return Ok(new
            {
                Message = $"Создано пользователей: {newUsers.Count}",
                Guids = createdGuids
            });
        }

        [Authorize]
        [HttpPut("{guid}/details")]
        public IActionResult UpdateDetails(Guid guid, [FromBody] DTOs.UpdateDetailsDto dto)
        {
            var currentLogin = User.Identity?.Name;
            var userToUpdate = _userService.GetUsers().FirstOrDefault(u => u.Guid == guid && !u.RevokedOn.HasValue);

            if (userToUpdate == null)
                return NotFound("Пользователь не найден или деактивирован");

            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);
            if (currentUser == null)
                return NotFound("Текущий пользователь не найден или деактивирован");

            if (!currentUser.Admin && currentUser.Guid != userToUpdate.Guid)
                return StatusCode(403, "Вы можете редактировать только свои данные");

            if (!IsValidName(dto.Name))
                return BadRequest("Имя должно содержать только латинские или русские буквы");

            userToUpdate.Name = dto.Name;
            userToUpdate.Gender = dto.Gender;
            userToUpdate.Birthday = dto.Birthday;
            userToUpdate.ModifiedOn = DateTime.UtcNow;
            userToUpdate.ModifiedBy = currentLogin;

            return Ok("Данные обновлены");
        }

        [Authorize]
        [HttpPut("{guid}/password")]
        public IActionResult UpdatePassword(Guid guid, [FromBody] DTOs.UpdatePasswordDto dto)
        {
            var currentLogin = User.Identity?.Name;
            var userToUpdate = _userService.GetUsers().FirstOrDefault(u => u.Guid == guid && !u.RevokedOn.HasValue);

            if (userToUpdate == null)
                return NotFound("Пользователь не найден или деактивирован");

            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);
            if (currentUser == null)
                return NotFound("Текущий пользователь не найден или деактивирован");

            if (!currentUser.Admin && currentUser.Guid != userToUpdate.Guid)
                return StatusCode(403, "Вы можете менять пароль только своему аккаунту");

            if (!currentUser.Admin && userToUpdate.Password != dto.OldPassword)
                return BadRequest("Неверный текущий пароль");

            if (!IsValidPassword(dto.NewPassword))
                return BadRequest("Пароль должен содержать только латинские буквы и цифры");

            userToUpdate.Password = dto.NewPassword;
            userToUpdate.ModifiedOn = DateTime.UtcNow;
            userToUpdate.ModifiedBy = currentLogin;

            return Ok("Пароль изменён");
        }

        [Authorize]
        [HttpPut("{guid}/login")]
        public IActionResult UpdateLogin(Guid guid, [FromBody] DTOs.UpdateLoginDto dto)
        {
            var currentLogin = User.Identity?.Name;
            var userToUpdate = _userService.GetUsers().FirstOrDefault(u => u.Guid == guid && !u.RevokedOn.HasValue);

            if (userToUpdate == null)
                return NotFound("Пользователь не найден или деактивирован");

            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);
            if (currentUser == null)
                return NotFound("Текущий пользователь не найден или деактивирован");

            if (!currentUser.Admin && currentUser.Guid != userToUpdate.Guid)
                return StatusCode(403, "Вы можете менять логин только своему аккаунту");

            if (!IsValidLogin(dto.NewLogin))
                return BadRequest("Логин должен содержать только латинские буквы и цифры");

            if (_userService.GetUsers().Any(u => u.Login == dto.NewLogin && !u.RevokedOn.HasValue))
                return Conflict("Этот логин уже занят");

            userToUpdate.Login = dto.NewLogin;
            userToUpdate.ModifiedOn = DateTime.UtcNow;
            userToUpdate.ModifiedBy = currentLogin;

            return Ok("Логин изменён");
        }

        [Authorize]
        [HttpGet("active")]
        public IActionResult GetAllActiveUsers()
        {
            var currentLogin = User.Identity?.Name;
            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);

            if (currentUser == null || !currentUser.Admin)
                return StatusCode(403, "Только администратор может просматривать список пользователей");

            var activeUsers = _userService.GetUsers()
                .Where(u => !u.RevokedOn.HasValue)
                .OrderBy(u => u.CreatedOn)
                .Select(u => new
                {
                    u.Guid,
                    u.Login,
                    u.Name,
                    u.Gender,
                    u.Birthday,
                    u.Admin,
                    u.CreatedOn
                });

            return Ok(activeUsers);
        }

        [Authorize]
        [HttpGet("{login}")]
        public IActionResult GetUserByLogin(string login)
        {
            var currentLogin = User.Identity?.Name;
            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);

            if (currentUser == null || !currentUser.Admin)
                return StatusCode(403, "Только администратор может запрашивать пользователей");

            var user = _userService.GetUsers().FirstOrDefault(u => u.Login == login && !u.RevokedOn.HasValue);
            if (user == null)
                return NotFound("Пользователь не найден или неактивен");

            return Ok(new
            {
                user.Login,
                user.Name,
                user.Gender,
                user.Birthday,
                IsActive = user.RevokedOn == null
            });
        }

        [Authorize]
        [HttpGet("auth")]
        public IActionResult GetUserByLoginAndPassword([FromQuery] string login, [FromQuery] string password)
        {
            var currentLogin = User.Identity?.Name;
            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);

            if (currentUser == null || currentUser.Login != login || currentUser.Password != password || currentUser.RevokedOn.HasValue)
                return StatusCode(403, "Вы можете получать данные только о себе");

            return Ok(currentUser);
        }

        [Authorize]
        [HttpGet("older-than/{years}")]
        public IActionResult GetUsersOlderThan(int years)
        {
            var currentLogin = User.Identity?.Name;
            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);

            if (currentUser == null || !currentUser.Admin)
                return StatusCode(403, "Только администратор может запрашивать пользователей по возрасту");

            if (years <= 0)
                return BadRequest("Укажите корректный возраст");

            var thresholdDate = DateTime.UtcNow.AddYears(-years);
            var result = _userService.GetUsers()
                .Where(u => !u.RevokedOn.HasValue && u.Birthday.HasValue && u.Birthday.Value < thresholdDate)
                .Select(u => new
                {
                    u.Login,
                    u.Name,
                    Age = (int)((DateTime.UtcNow - u.Birthday.Value).TotalDays / 365.25)
                });

            return Ok(result);
        }

        [Authorize]
        [HttpDelete("{login}")]
        public IActionResult DeleteUser(string login)
        {
            var currentLogin = User.Identity?.Name;
            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);

            if (currentUser == null || !currentUser.Admin)
                return StatusCode(403, "Только администратор может удалять пользователей");

            var userToDelete = _userService.GetUsers().FirstOrDefault(u => u.Login == login && !u.RevokedOn.HasValue);
            if (userToDelete == null)
                return NotFound("Пользователь не найден или уже удален");

            userToDelete.RevokedOn = DateTime.UtcNow;
            userToDelete.RevokedBy = currentUser.Login;
            userToDelete.ModifiedOn = DateTime.UtcNow;
            userToDelete.ModifiedBy = currentUser.Login;

            return Ok("Пользователь удален");
        }

        [Authorize]
        [HttpPut("{login}/restore")]
        public IActionResult RestoreUser(string login)
        {
            var currentLogin = User.Identity?.Name;
            var currentUser = _userService.GetUsers().FirstOrDefault(u => u.Login == currentLogin && !u.RevokedOn.HasValue);

            if (currentUser == null || !currentUser.Admin)
                return StatusCode(403, "Только администратор может восстанавливать пользователей");

            var userToRestore = _userService.GetUsers().FirstOrDefault(u => u.Login == login && u.RevokedOn.HasValue);
            if (userToRestore == null)
                return NotFound("Пользователь не найден или не удален");

            userToRestore.RevokedOn = null;
            userToRestore.RevokedBy = null;
            userToRestore.ModifiedOn = DateTime.UtcNow;
            userToRestore.ModifiedBy = currentUser.Login;

            return Ok("Пользователь восстановлен");
        }

        private bool IsValidLogin(string login) =>
            !string.IsNullOrWhiteSpace(login) && login.All(c => char.IsLetterOrDigit(c));

        private bool IsValidPassword(string password) =>
            !string.IsNullOrWhiteSpace(password) && password.All(c => char.IsLetterOrDigit(c));

        private bool IsValidName(string name) =>
            !string.IsNullOrWhiteSpace(name) && name.All(c => char.IsLetter(c) || c == ' ');
    }
}