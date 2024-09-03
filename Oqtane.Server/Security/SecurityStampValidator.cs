using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Oqtane.Extensions;
using Oqtane.Repository;

namespace Oqtane.Security
{
    public class SecurityStampValidator(
        IUserRepository userRepository,
        IUserRoleRepository userRoleRepository,
        IOptions<IdentityOptions> identityOptions,
        IOptions<SecurityStampValidatorOptions> options,
        SignInManager<IdentityUser> signInManager,
        ILoggerFactory logger)
        : SecurityStampValidator<IdentityUser>(options, signInManager, logger)
    {
        protected override async Task<IdentityUser> VerifySecurityStamp(ClaimsPrincipal principal)
        {
            var userManager = SignInManager.UserManager;
            var user = await userManager.FindByNameAsync(principal.Username());

            if (user is null)
            {
                return null;
            }
            else if (!userManager.SupportsUserSecurityStamp)
            {
                return user;
            }
            else
            {
                var principalStamp = principal.FindFirstValue(identityOptions.Value.ClaimsIdentity.SecurityStampClaimType);
                var userStamp = await userManager.GetSecurityStampAsync(user);
                return principalStamp == userStamp ? user : null;
            }
        }

        /// <summary>
        /// Called when the security stamp has been verified.
        /// </summary>
        /// <param name="identityUser">The identityUser who has been verified.</param>
        /// <param name="context">The <see cref="CookieValidatePrincipalContext"/>.</param>
        /// <returns>A task.</returns>
        protected override async Task SecurityStampVerified(IdentityUser identityUser, CookieValidatePrincipalContext context)
        {
            var alias = context.HttpContext.GetAlias();
            var user = userRepository.GetUser(identityUser.UserName);
            var userRoles = userRoleRepository.GetUserRoles(user.UserId, alias.SiteId).ToList();

            if (context.Principal != null)
            {
                var securityStampClaim =
                    context.Principal.Claims.FirstOrDefault(c => c.Type == identityOptions.Value.ClaimsIdentity.SecurityStampClaimType);

                var identity = UserSecurity.CreateClaimsIdentity(alias, user, userRoles);

                if (securityStampClaim != null)
                    identity.AddClaim(new Claim(securityStampClaim.Type, securityStampClaim.Value));

                var newPrincipal = new ClaimsPrincipal(identity);
                
                if (Options.OnRefreshingPrincipal != null)
                {
                    var replaceContext = new SecurityStampRefreshingPrincipalContext
                    {
                        CurrentPrincipal = context.Principal,
                        NewPrincipal = newPrincipal
                    };

                    // Note: a null principal is allowed and results in a failed authentication.
                    await Options.OnRefreshingPrincipal(replaceContext);
                    newPrincipal = replaceContext.NewPrincipal;
                }

                // REVIEW: note we lost login authentication method
                context.ReplacePrincipal(newPrincipal);
                context.ShouldRenew = true;
            }

            if (!context.Options.SlidingExpiration)
            {
                // On renewal calculate the new ticket length relative to now to avoid
                // extending the expiration.
                context.Properties.IssuedUtc = TimeProvider.GetUtcNow();
            }
        }

    }
}
