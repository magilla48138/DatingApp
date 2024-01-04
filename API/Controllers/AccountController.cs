
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Authorize]
    public class AccountController : BaseAPIController
    {
        private readonly DataContext _context;

        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _context = context;
            _tokenService = tokenService;
        }

        [HttpPost("register")] // POST: api/account/register

        public async Task<ActionResult<UserDto>> Register (RegisterDto registerDto)
        {

            if ( await UserExists (registerDto.userName) )
              return BadRequest ("Username is taken.");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.userName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);

            await _context.SaveChangesAsync();

            return new UserDto { userName = user.UserName, token = _tokenService.CreateToken(user)};

        }

        [HttpPost("login")]

        public async Task<ActionResult<UserDto>> Login (LoginDto loginDto)
        {
            var user = await _context.Users.SingleOrDefaultAsync (x => x.UserName == loginDto.userName);

            if ( user == null )
              return Unauthorized ("Invalid username");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.password));

            for ( int j = 0; j < computedHash.Length; j++ )
              if ( computedHash[j] != user.PasswordHash[j] )
                return Unauthorized("Invalid Password");

            return new UserDto { userName = user.UserName, token =  _tokenService.CreateToken(user)};

            
        }

        private async Task<Boolean> UserExists (string username)
        {
          return await _context.Users.AnyAsync(x => x.UserName == username.ToLower ());
        }
    }
}