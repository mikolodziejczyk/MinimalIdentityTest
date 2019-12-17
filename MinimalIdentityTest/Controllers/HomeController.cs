using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity.Owin;
using System.Security.Claims;
using MinimalIdentityTest.Models;
using System.Threading.Tasks;
using System.Data.Entity;
using System.Net;

namespace MinimalIdentityTest.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationUserManager userManager;
        private readonly ApplicationSignInManager signInManager;

        public HomeController(ApplicationUserManager userManager, ApplicationSignInManager signInManager)
        {
            this.userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
            this.signInManager = signInManager ?? throw new ArgumentNullException(nameof(signInManager));
        }

        public ActionResult Index()
        {
            return View();
        }

        [Authorize(Roles = "Admin")]
        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            var userStore = new UserStore<IdentityUser>();
            IdentityUser[] identityUsers = userStore.Users.ToArray();

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            Claim companyDaxCode = ((ClaimsIdentity)User.Identity).FindFirst("ComanyDaxCode");
            string daxCode = companyDaxCode.Value;

            return View();
        }

        [HttpGet]
        public ActionResult Register()
        {
            return View(new RegisterVM());
        }


        [HttpPost]
        public ActionResult Register(RegisterVM model)
        {
            ApplicationUser user = new ApplicationUser() { UserName = model.Email, Email = model.Email };
            IdentityResult result = userManager.Create(user, model.Password);

            if (result.Succeeded)
            {
                var authenticationManager = HttpContext.GetOwinContext().Authentication;
                var userIdentity = userManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);
                authenticationManager.SignIn(new AuthenticationProperties() { }, userIdentity);

                // r = string.Format("User {0} was created successfully!", user.UserName);
                return RedirectToAction("Index");
            }
            else
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault());
            }

            return View(model);
        }

        [HttpGet]
        public ActionResult RegisterWithEmail()
        {
            return View("Register", new RegisterVM());
        }


        [HttpPost]
        public ActionResult RegisterWithEmail(RegisterVM model)
        {
            ApplicationUser user = new ApplicationUser() { UserName = model.Email, Email = model.Email };
            IdentityResult result = userManager.Create(user, model.Password);

            if (result.Succeeded)
            {
                string code = userManager.GenerateEmailConfirmationToken(user.Id);

                var callbackUrl = Url.Action("ConfirmEmail", "Home", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                userManager.SendEmail(user.Id, "Confirm your account", "Please confirm your account by clicking this link: <a href=\"" + callbackUrl + "\">link</a>");

                return RedirectToAction("Index");
            }
            else
            {
                ModelState.AddModelError("", result.Errors.FirstOrDefault());
            }

            return View("Register", model);
        }


        [AllowAnonymous]
        public async Task<ActionResult> ConfirmEmail(string userId, string code)
        {
            if (userId == null || code == null)
            {
                return View("Error");
            }
            var result = await userManager.ConfirmEmailAsync(userId, code);
            return View(result.Succeeded ? "ConfirmEmail" : "Error");
        }

        [HttpGet]
        public ActionResult SignIn(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View(new SignInVM());
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> SignIn(SignInVM model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            ApplicationUser user = userManager.FindByName(model.UserName);

            if (user.AccessFailedCount > 3)
            {
                // require captcha
            }


            if (!user.EmailConfirmed)
            {
                ModelState.AddModelError("", "Your e-mail has not been confirmed. Please find an e-mail in your mailbox and click the link we have sent you to confirm your e-mail.");
                return View(model);
            }

            if (!user.IsApproved)
            {
                ModelState.AddModelError("", "The user has not been yet approved by the administrator.");
                return View(model);
            }

            if (user.IsDisabled)
            {
                ModelState.AddModelError("", "The user has been disabled. You cannot log in.");
                return View(model);
            }



            var result = await signInManager.PasswordSignInAsync(model.UserName, model.Password, isPersistent: model.RememberMe, shouldLockout: true);
            switch (result)
            {
                case SignInStatus.Success:
                    return RedirectToLocal(returnUrl);
                //case SignInStatus.LockedOut:
                //    return View("Lockout");
                //case SignInStatus.RequiresVerification:
                //    return RedirectToAction("SendCode", new { ReturnUrl = returnUrl, RememberMe = model.RememberMe });
                case SignInStatus.Failure:
                default:
                    ModelState.AddModelError("", "Invalid login attempt.");
                    return View(model);
            }
        }

        public ActionResult SignOut()
        {
            var authenticationManager = HttpContext.GetOwinContext().Authentication;
            authenticationManager.SignOut();
            return RedirectToAction("Index");
        }

        [HttpGet]
        public ActionResult ChangePassword()
        {
            return View(new ChangePasswordVM());
        }

        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordVM model)
        {
            if (ModelState.IsValid)
            {
                string userId = User.Identity.GetUserId<string>();

                IdentityResult identityResult = userManager.ChangePassword(userId, model.CurrentPassword, model.NewPassword);

                if (!identityResult.Succeeded)
                {
                    ModelState.AddModelError("", identityResult.Errors.First());
                    return View(model);
                }

                return RedirectToAction("Index");
            }
            else
            {
                return View(model);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ForgotPassword
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/ForgotPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await userManager.FindByNameAsync(model.Email);
                if (user == null || !(await userManager.IsEmailConfirmedAsync(user.Id)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return View("ForgotPasswordConfirmation");
                }

                // For more information on how to enable account confirmation and password reset please visit https://go.microsoft.com/fwlink/?LinkID=320771
                // Send an email with this link
                string code = await userManager.GeneratePasswordResetTokenAsync(user.Id);
                var callbackUrl = Url.Action("ResetPassword", "Home", new { userId = user.Id, code = code }, protocol: Request.Url.Scheme);
                await userManager.SendEmailAsync(user.Id, "Reset Password", "Please reset your password by clicking <a href=\"" + callbackUrl + "\">here</a>");
                return RedirectToAction("ForgotPasswordConfirmation", "Home");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ForgotPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        //
        // GET: /Account/ResetPassword
        [AllowAnonymous]
        public ActionResult ResetPassword(string code)
        {
            return code == null ? View("Error") : View();
        }

        //
        // POST: /Account/ResetPassword
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await userManager.FindByNameAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction("ResetPasswordConfirmation", "Home");
            }
            var result = await userManager.ResetPasswordAsync(user.Id, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction("ResetPasswordConfirmation", "Home");
            }


            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }

            return View();
        }

        //
        // GET: /Account/ResetPasswordConfirmation
        [AllowAnonymous]
        public ActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        public ActionResult EnsureRoles()
        {
            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(new IdentityDbContext()));


            string roleName = "Admin";

            if (!roleManager.RoleExists(roleName))
            {
                var role = new IdentityRole();
                role.Name = roleName;
                roleManager.Create(role);

            }

            // bool isInRole = userManager.IsInRole(this.User.Identity.GetUserId(), roleName);
            // string[] roles = userManager.GetRoles(this.User.Identity.GetUserId()).ToArray();

            if (!this.User.IsInRole(roleName))
            {
                userManager.AddToRole<ApplicationUser, string>(this.User.Identity.GetUserId(), roleName);
            }

            return Content("OK");
        }

        public ActionResult ForceLogout()
        {
            userManager.UpdateSecurityStamp("681042de-0408-4700-85db-3de2d0bd967c");
            return Content("OK");
        }

        public ActionResult ToggleDisabledForUser(string id, bool isDisabled = true)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            ApplicationUser user = userManager.FindById(id);

            if (user == null)
            {
                throw new InvalidOperationException();
            }

            user.IsDisabled = isDisabled;

            IdentityResult r = userManager.Update(user);

            if (!r.Succeeded)
            {
                string[] erorrs = r.Errors.ToArray();
                // log them or return
                throw new InvalidOperationException();
            }

            return Content("OK");
        }

        public async Task<ActionResult> Delete(string id)
        {

            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }

            var user = await userManager.FindByIdAsync(id);
            var logins = user.Logins;
            var rolesForUser = await userManager.GetRolesAsync(id);

            ApplicationDbContext context = (ApplicationDbContext)userManager.UserStore.Context;

            using (var transaction = context.Database.BeginTransaction())
            {
                foreach (var login in logins.ToList())
                {
                    await userManager.RemoveLoginAsync(login.UserId, new UserLoginInfo(login.LoginProvider, login.ProviderKey));
                }

                foreach (var role in rolesForUser.ToList())
                {
                    var result = await userManager.RemoveFromRoleAsync(user.Id, role);
                }

                await userManager.DeleteAsync(user);
                transaction.Commit();
            }

            return RedirectToAction("Index");

        }
    }
}