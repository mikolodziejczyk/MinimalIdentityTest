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

namespace MinimalIdentityTest.Controllers
{
    public class HomeController : Controller
    {
        private readonly ApplicationUserManager userManager;

        public HomeController(ApplicationUserManager userManager)
        {
            this.userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
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

            string r;
            
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
        public ActionResult SignIn()
        {
            return View();
        }

        [HttpPost]
        public ActionResult SignIn(string UserName, string Password)
        {
            UserStore<IdentityUser> userStore = new UserStore<IdentityUser>();
            UserManager<IdentityUser> userManager = new UserManager<IdentityUser>(userStore);
            var user = userManager.Find(UserName, Password);

            if (user != null)
            {
                IAuthenticationManager authenticationManager = HttpContext.GetOwinContext().Authentication;
                ClaimsIdentity userIdentity = userManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);

                authenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = false }, userIdentity);
                return RedirectToAction("Index");
            }
            else
            {
                return Content("Invalid username or password.");
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
    }
}