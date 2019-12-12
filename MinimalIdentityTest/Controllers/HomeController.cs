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
            IdentityUser user = new IdentityUser() { UserName = model.Email, Email = model.Email };
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

            IdentityUser user = userManager.FindByName(model.UserName);

            if (user.AccessFailedCount > 3)
            {
                // require captcha
            }

            // This doesn't count login failures towards account lockout
            // To enable password failures to trigger account lockout, change to shouldLockout: true
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

            if (!this.User.IsInRole(roleName)) // IsInRole doesn't work.
            {
                userManager.AddToRole<IdentityUser, string>(this.User.Identity.GetUserId(), roleName);
            }

            return Content("OK");
        }
    }
}