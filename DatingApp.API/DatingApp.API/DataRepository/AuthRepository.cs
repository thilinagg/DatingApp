using DatingApp.API.Data;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DatingApp.API.DataRepository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext context;
        public AuthRepository(DataContext context)
        {
            this.context = context;
        }
        public async Task<User> Login(string userName, string password)
        {
            var user = await context.Users.FirstOrDefaultAsync(u => u.UserName == userName);

            if (user == null)
            {
                return null;
            }

            if(!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
            {
                return null;
            }

            return user;
        }

        public async Task<User> Register(User user, string password)
        {
            byte[] passwordHash, paaswordSalt;
            CrearePaqsswordHash(password, out passwordHash, out paaswordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = paaswordSalt;

            await context.AddAsync(user);
            await context.SaveChangesAsync();

            return user;
        }

        public async Task<bool> UserExist(string userName)
        {
            if(await context.Users.AnyAsync(u => u.UserName == userName))
            {
                return true;
            }
            return false;
        }

        private void CrearePaqsswordHash(string password, out byte[] passwordHash, out byte[] paaswordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512())
            {
                paaswordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                for (int i = 0; i < computedHash.Length; i++)
                {
                    if (passwordHash[i] != computedHash[i])
                    {
                        return false;
                    }
                }
                return true;
            }
        }

    }
}
