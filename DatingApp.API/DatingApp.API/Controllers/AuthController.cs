using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthRepository authRepository;

        public AuthController(IAuthRepository authRepository)
        {
            this.authRepository = authRepository;
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody]UserRegisterDto userRegisterDto)
        {
            userRegisterDto.UserName = userRegisterDto.UserName.ToLower();

            if (await authRepository.UserExist(userRegisterDto.UserName))
            {
                ModelState.AddModelError("UserName", "User Name already exist");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userToCreate = new User
            {
                UserName = userRegisterDto.UserName
            };

            var createUser = await authRepository.Register(userToCreate, userRegisterDto.Password);

            return StatusCode(200);
        }

        [HttpPost("login")]
        public async Task<ActionResult> Login([FromBody]UserLoginDto userLoginDto)
        {
            var user =  await authRepository.Login(userLoginDto.UserName.ToLower(), userLoginDto.Password);

            if (user == null)
            {
                return Unauthorized();
            }

            //generate the token
            var tockenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("super secret key");
            var tockenDescription = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                    new Claim(ClaimTypes.Name, user.UserName)
                }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha512Signature)
            };
            var tocken = tockenHandler.CreateToken(tockenDescription);
            var tockenString = tockenHandler.WriteToken(tocken);

            return Ok(new { tockenString });
        }

    }
}