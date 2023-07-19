// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

using Dynamics365;
using Microsoft.Dynamics365.UIAutomation.Api.UCI.DTO;
using Microsoft.Dynamics365.UIAutomation.Browser;
using Newtonsoft.Json.Linq;
using OneAutomationFramework.Drivers.Selenium;
using OpenQA.Selenium;
using OpenQA.Selenium.Interactions;
using OtpNet;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Security;
using System.Web;
using System.Windows.Forms;
using Keys = OpenQA.Selenium.Keys;

namespace Microsoft.Dynamics365.UIAutomation.Api.UCI
{
    public class WebClient : IDisposable
    {
        public readonly IWebDriver driver;
        public WebClient(IWebDriver _driver)
        {
            this.driver = _driver;
        }


        internal bool InitializeModes()
        {
            driver.SwitchTo().DefaultContent();

            // Wait for main page to load before attempting this. If you don't do this it might still be authenticating and the URL will be wrong
            WaitForMainPage();

            string uri = driver.Url;
            if (string.IsNullOrEmpty(uri))
                return false;

            var prevQuery = GetUrlQueryParams(uri);
            bool requireRedirect = false;
            string queryParams = "";
            if (prevQuery.Get("flags") == null)
            {
                queryParams += "&flags=easyreproautomation=true";

                requireRedirect = true;
            }

            if (prevQuery.Get("perf") == null)
            {
                queryParams += "&perf=true";
                requireRedirect = true;
            }

            if (!requireRedirect)
                return true;

            var testModeUri = uri + queryParams;
            driver.Navigate().GoToUrl(testModeUri);

            // Again wait for loading
            WaitForMainPage();
            return true;
        }

        private NameValueCollection GetUrlQueryParams(string url)
        {
            if (string.IsNullOrEmpty(url))
                return null;

            Uri uri = new Uri(url);
            var query = uri.Query.ToLower();
            NameValueCollection result = HttpUtility.ParseQueryString(query);
            return result;
        }


        public string[] OnlineDomains { get; set; }

        #region PageWaits
        internal bool WaitForMainPage(TimeSpan timeout, string errorMessage)
            => WaitForMainPage(timeout, null, () => throw new InvalidOperationException(errorMessage));

        internal bool WaitForMainPage(TimeSpan? timeout = null, Action<IWebElement> successCallback = null, Action failureCallback = null)
        {
            timeout = timeout ?? Constants.DefaultTimeout;
            successCallback = successCallback ?? (
                                  _ =>
                                  {
                                      bool isUCI = driver.HasElement(By.XPath(Elements.Xpath[Reference.Login.CrmUCIMainPage]));
                                      if (isUCI)
                                          driver.WaitForTransaction();
                                  });

            var xpathToMainPage = By.XPath(Elements.Xpath[Reference.Login.CrmMainPage]);
            var element = driver.WaitUntilAvailable(xpathToMainPage, timeout, successCallback, failureCallback);
            return element != null;
        }

        #endregion

        #region Login

        public string GetValueFromConfig(string key, string subkey = null)
        {
            var files = Directory.GetFiles(AppDomain.CurrentDomain.BaseDirectory, "*Config.json", SearchOption.AllDirectories).ToList();
            var fileName = files.Where(x => x.Contains($"Dynamic365Config.json")).FirstOrDefault();
            var content = File.ReadAllText(fileName);
            JObject jsonObj = JObject.Parse(content);
            if (subkey is null)
                return jsonObj[key].ToString();
            return jsonObj[key][subkey].ToString();
        }

        internal LoginResult Login(Uri uri)
        {
            var username = GetValueFromConfig("Username").ToSecureString();
            if (username == null)
                return PassThroughLogin(uri);

            var password = GetValueFromConfig("Password").ToSecureString();
            return Login(driver,uri, username, password);
        }

        public LoginResult Login(IWebDriver driver, Uri uri, SecureString username, SecureString password, SecureString mfaSecretKey = null, Action<LoginRedirectEventArgs> redirectAction = null)
        {
            bool online = !(OnlineDomains != null && !OnlineDomains.Any(d => uri.Host.EndsWith(d)));
            driver.Navigate().GoToUrl(uri);

            if (!online)
                return LoginResult.Success;

            driver.ClickIfVisible(By.Id(Elements.ElementId[Reference.Login.UseAnotherAccount]));

            bool waitingForOtc = false;
            bool success = EnterUserName(driver, username);
            if (!success)
            {
                var isUserAlreadyLogged = IsUserAlreadyLogged();
                if (isUserAlreadyLogged)
                {
                    SwitchToDefaultContent(driver);
                    return LoginResult.Success;
                }

                ThinkTime(1000);
                waitingForOtc = GetOtcInput(driver) != null;

                if (!waitingForOtc)
                    throw new Exception($"Login page failed. {Reference.Login.UserId} not found.");
            }

            if (!waitingForOtc)
            {
                driver.ClickIfVisible(By.Id("aadTile"));
                ThinkTime(1000);

                //If expecting redirect then wait for redirect to trigger
                if (redirectAction != null)
                {
                    //Wait for redirect to occur.
                    ThinkTime(3000);

                    redirectAction.Invoke(new LoginRedirectEventArgs(username, password, driver));
                    return LoginResult.Redirect;
                }

                EnterPassword(driver, password);
                ThinkTime(1000);
            }

            int attempts = 0;
            bool entered;
            do
            {
                entered = EnterOneTimeCode(driver, mfaSecretKey);
                success = ClickStaySignedIn(driver) || IsUserAlreadyLogged();
                attempts++;
            }
            while (!success && attempts <= Constants.DefaultRetryAttempts); // retry to enter the otc-code, if its fail & it is requested again 

            if (entered && !success)
                throw new InvalidOperationException("Something went wrong entering the OTC. Please check the MFA-SecretKey in configuration.");

            return success ? LoginResult.Success : LoginResult.Failure;
        }

        private bool IsUserAlreadyLogged() => WaitForMainPage(2.Seconds());

        private static string GenerateOneTimeCode(string key)
        {
            // credits:
            // https://dev.to/j_sakamoto/selenium-testing---how-to-sign-in-to-two-factor-authentication-2joi
            // https://www.nuget.org/packages/Otp.NET/
            byte[] base32Bytes = Base32Encoding.ToBytes(key);

            var totp = new Totp(base32Bytes);
            var result = totp.ComputeTotp(); // <- got 2FA code at this time!
            return result;
        }

        private bool EnterUserName(IWebDriver driver, SecureString username)
        {
            var input = driver.WaitUntilAvailable(By.XPath(Elements.Xpath[Reference.Login.UserId]), new TimeSpan(0, 0, 30));
            if (input == null)
                return false;

            input.SendKeys(username.ToUnsecureString());
            input.SendKeys(OpenQA.Selenium.Keys.Enter);
            return true;
        }

        private static void EnterPassword(IWebDriver driver, SecureString password)
        {
            var input = driver.FindElement(By.XPath(Elements.Xpath[Reference.Login.LoginPassword]));
            input.SendKeys(password.ToUnsecureString());
            input.Submit();
        }

        private bool EnterOneTimeCode(IWebDriver driver, SecureString mfaSecretKey)
        {
            try
            {
                IWebElement input = GetOtcInput(driver); // wait for the dialog, even if key is null, to print the right error
                if (input == null)
                    return true;

                string key = mfaSecretKey?.ToUnsecureString(); // <- this 2FA secret key.
                if (string.IsNullOrWhiteSpace(key))
                    throw new InvalidOperationException("The application is wait for the OTC but your MFA-SecretKey is not set. Please check your configuration.");

                var oneTimeCode = GenerateOneTimeCode(key);
                SetInputValue(driver, input, oneTimeCode, 1.Seconds());
                input.Submit();
                return true; // input found & code was entered
            }
            catch (Exception e)
            {
                var message = $"An Error occur entering OTC. Exception: {e.Message}";
                Trace.TraceInformation(message);
                throw new InvalidOperationException(message, e);
            }
        }


        private static IWebElement GetOtcInput(IWebDriver driver)
            => driver.WaitUntilAvailable(By.XPath(Elements.Xpath[Reference.Login.OneTimeCode]), TimeSpan.FromSeconds(2));

        private static bool ClickStaySignedIn(IWebDriver driver)
        {
            var xpath = By.XPath(Elements.Xpath[Reference.Login.StaySignedIn]);
            var element = driver.ClickIfVisible(xpath, 2.Seconds());
            return element != null;
        }

        private static void SwitchToDefaultContent(IWebDriver driver)
        {
            SwitchToMainFrame(driver);

            //Switch Back to Default Content for Navigation Steps
            driver.SwitchTo().DefaultContent();
        }

        private static void SwitchToMainFrame(IWebDriver driver)
        {
            driver.WaitForPageToLoad();
            driver.SwitchTo().Frame(0);
            driver.WaitForPageToLoad();
        }

        internal LoginResult PassThroughLogin(Uri uri)
        {
            driver.Navigate().GoToUrl(uri);

            WaitForMainPage(60.Seconds(),
                _ =>
                {
                    //determine if we landed on the Unified Client Main page
                    var isUCI = driver.HasElement(By.XPath(Elements.Xpath[Reference.Login.CrmUCIMainPage]));
                    if (isUCI)
                    {
                        driver.WaitForPageToLoad();
                        driver.WaitForTransaction();
                    }
                    else
                        //else we landed on the Web Client main page or app picker page
                        SwitchToDefaultContent(driver);
                },
                () => throw new InvalidOperationException("Load Main Page Fail.")
            );

            return LoginResult.Success;
        }


        public void ADFSLoginAction(LoginRedirectEventArgs args)

        {
            //Login Page details go here.  You will need to find out the id of the password field on the form as well as the submit button. 
            //You will also need to add a reference to the Selenium Webdriver to use the base driver. 
            //Example

            var driver = args.Driver;

            driver.FindElement(By.Id("passwordInput")).SendKeys(args.Password.ToUnsecureString());
            driver.ClickWhenAvailable(By.Id("submitButton"), TimeSpan.FromSeconds(2));

            //Insert any additional code as required for the SSO scenario

            //Wait for CRM Page to load
            WaitForMainPage(TimeSpan.FromSeconds(60), "Login page failed.");
            SwitchToMainFrame(driver);
        }

        public void MSFTLoginAction(LoginRedirectEventArgs args)

        {
            //Login Page details go here.  You will need to find out the id of the password field on the form as well as the submit button. 
            //You will also need to add a reference to the Selenium Webdriver to use the base driver. 
            //Example

            var driver = args.Driver;

            //d.FindElement(By.Id("passwordInput")).SendKeys(args.Password.ToUnsecureString());
            //d.ClickWhenAvailable(By.Id("submitButton"), TimeSpan.FromSeconds(2));

            //This method expects single sign-on

            ThinkTime(5000);

            driver.WaitUntilVisible(By.XPath("//div[@id=\"mfaGreetingDescription\"]"));

            var azureMFA = driver.FindElement(By.XPath("//a[@id=\"WindowsAzureMultiFactorAuthentication\"]"));
            azureMFA.Click(true);

            Thread.Sleep(20000);

            //Insert any additional code as required for the SSO scenario

            //Wait for CRM Page to load
            WaitForMainPage(TimeSpan.FromSeconds(60), "Login page failed.");
            SwitchToMainFrame(driver);
        }

        #endregion

        #region Navigation

        internal bool SignOut()
        {
            driver.WaitUntilClickable(By.XPath(AppElements.Xpath[AppReference.Navigation.AccountManagerButton])).Click();
            driver.WaitUntilClickable(By.XPath(AppElements.Xpath[AppReference.Navigation.AccountManagerSignOutButton])).Click();
            return driver.WaitForPageToLoad();
        }


        internal bool OpenApp(string appName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitForPageToLoad();
            driver.SwitchTo().DefaultContent();

            var query = GetUrlQueryParams(driver.Url);
            bool isSomeAppOpen = query.Get("appid") != null || query.Get("app") != null;

            bool success = false;
            if (!isSomeAppOpen)
                success = TryToClickInAppTile(appName, driver);
            else
                success = TryOpenAppFromMenu(driver, appName, AppReference.Navigation.UCIAppMenuButton) ||
                          TryOpenAppFromMenu(driver, appName, AppReference.Navigation.WebAppMenuButton);

            if (!success)
                throw new InvalidOperationException($"App Name {appName} not found.");

            InitializeModes();

            // Wait for app page elements to be visible (shell and sitemapLauncherButton)
            var shell = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Application.Shell]));
            var sitemapLauncherButton = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherButton]));

            success = shell != null && sitemapLauncherButton != null;

            if (!success)
                throw new InvalidOperationException($"App '{appName}' was found but app page was not loaded.");

            return true;
        }

        private bool TryOpenAppFromMenu(IWebDriver driver, string appName, string appMenuButton)
        {
            bool found = false;
            var xpathToAppMenu = By.XPath(AppElements.Xpath[appMenuButton]);
            driver.WaitUntilClickable(xpathToAppMenu, 5.Seconds(),
                        appMenu =>
                        {
                            appMenu.Click(true);
                            found = TryToClickInAppTile(appName, driver) || OpenAppFromMenu(driver, appName);
                        });
            return found;
        }

        internal bool OpenAppFromMenu(IWebDriver driver, string appName)
        {
            var container = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.AppMenuContainer]));
            var xpathToButton = "//nav[@aria-hidden='false']//button//*[text()='[TEXT]']".Replace("[TEXT]", appName);
            var button = container.ClickWhenAvailable(By.XPath(xpathToButton),
                                TimeSpan.FromSeconds(1)
                            );

            var success = (button != null);
            if (!success)
                Trace.TraceWarning($"App Name '{appName}' not found.");

            return success;
        }

        private static bool TryToClickInAppTile(string appName, IWebDriver driver)
        {
            string message = "Frame AppLandingPage is not loaded.";
            driver.WaitUntil(
                d =>
                {
                    try
                    {
                        driver.SwitchTo().Frame("AppLandingPage");
                        driver.WaitForPageToLoad();
                    }
                    catch (NoSuchFrameException ex)
                    {
                        message = $"{message} Exception: {ex.Message}";
                        Trace.TraceWarning(message);
                        return false;
                    }
                    return true;
                },
                10.Seconds()
                );

            var xpathToAppContainer = By.XPath(AppElements.Xpath[AppReference.Navigation.UCIAppContainer]);
            var xpathToappTile = By.XPath(AppElements.Xpath[AppReference.Navigation.UCIAppTile].Replace("[NAME]", appName));

            bool success = true;
            driver.WaitUntilVisible(xpathToAppContainer, TimeSpan.FromSeconds(5),
                appContainer => success = appContainer.ClickWhenAvailable(xpathToappTile, TimeSpan.FromSeconds(10)) == null
                );

            if (!success)
                Trace.TraceWarning(message);

            return success;
        }

        internal bool OpenGroupSubArea(string group, string subarea, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            //Make sure the sitemap-launcher is expanded - 9.1
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherButton])))
            {
                var expanded = bool.Parse(driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherButton])).GetAttribute("aria-expanded"));

                if (!expanded)
                    driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherButton]));
            }

            var groups = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.Navigation.SitemapMenuGroup]));
            var groupList = groups.FirstOrDefault(g => g.GetAttribute("aria-label").ToLowerString() == group.ToLowerString());
            if (groupList == null)
            {
                throw new NotFoundException($"No group with the name '{group}' exists");
            }

            var subAreaItems = groupList.FindElements(By.XPath(AppElements.Xpath[AppReference.Navigation.SitemapMenuItems]));
            var subAreaItem = subAreaItems.FirstOrDefault(a => a.GetAttribute("data-text").ToLowerString() == subarea.ToLowerString());
            if (subAreaItem == null)
            {
                throw new NotFoundException($"No subarea with the name '{subarea}' exists inside of '{group}'");
            }

            subAreaItem.Click(true);

            WaitForLoadArea(driver);
            return true;
        }

        internal bool OpenSubArea(string area, string subarea, int thinkTime = Constants.DefaultThinkTime)
        {
            //If the subarea is already in the left hand nav, click it
            var success = TryOpenSubArea(driver, subarea);
            if (!success)
            {
                success = TryOpenArea(area);
                if (!success)
                    throw new InvalidOperationException($"Area with the name '{area}' not found. ");

                success = TryOpenSubArea(driver, subarea);
                if (!success)
                    throw new InvalidOperationException($"No subarea with the name '{subarea}' exists inside of '{area}'.");
            }

            WaitForLoadArea(driver);
            return true;
        }

        private static void WaitForLoadArea(IWebDriver driver)
        {
            driver.WaitForPageToLoad();
            driver.WaitForTransaction();
        }

        public bool OpenSubArea(string subarea)
        {
            var success = TryOpenSubArea(driver, subarea);
            WaitForLoadArea(driver);
            return success;
        }

        private bool TryOpenSubArea(IWebDriver driver, string subarea)
        {
            subarea = subarea.ToLowerString();
            var navSubAreas = GetSubAreaMenuItems(driver);

            var found = navSubAreas.TryGetValue(subarea, out var element);
            if (found)
            {
                var strSelected = element.GetAttribute("aria-selected");
                bool.TryParse(strSelected, out var selected);
                if (!selected)
                {
                    element.Click(true);
                }
                else
                {
                    // This will result in navigating back to the desired subArea -- even if already selected.
                    // Example: If context is an Account entity record, then a call to OpenSubArea("Sales", "Accounts"),
                    // this will click on the Accounts subArea and go back to the grid view
                    element.Click(true);
                }
            }
            return found;
        }

        public bool OpenArea(string subarea)
        {
            var success = TryOpenArea(subarea);
            WaitForLoadArea(driver);
            return success;
        }

        private bool TryOpenArea(string area)
        {
            area = area.ToLowerString();
            var areas = OpenAreas(area);

            IWebElement menuItem;
            bool found = areas.TryGetValue(area, out menuItem);
            if (found)
            {
                var strSelected = menuItem.GetAttribute("aria-checked");
                bool selected;
                bool.TryParse(strSelected, out selected);
                if (!selected)
                    menuItem.Click(true);
            }
            return found;
        }

        public Dictionary<string, IWebElement> OpenAreas(string area, int thinkTime = Constants.DefaultThinkTime)
        {
            //  9.1 ?? 9.0.2 <- inverted order (fallback first) run quickly
            var areas = OpenMenuFallback(area) ?? OpenMenu();

            if (!areas.ContainsKey(area))
                throw new InvalidOperationException($"No area with the name '{area}' exists.");

            return areas;
        }

        public Dictionary<string, IWebElement> OpenMenu(int thinkTime = Constants.DefaultThinkTime)
        {
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.AreaButton]));

            var result = GetMenuItemsFrom(driver, AppReference.Navigation.AreaMenu);
            return result;
        }

        public Dictionary<string, IWebElement> OpenMenuFallback(string area, int thinkTime = Constants.DefaultThinkTime)
        {
            //Make sure the sitemap-launcher is expanded - 9.1
            var xpathSiteMapLauncherButton = By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherButton]);
            bool success = driver.TryFindElement(xpathSiteMapLauncherButton, out IWebElement launcherButton);
            if (success)
            {
                bool expanded = bool.Parse(launcherButton.GetAttribute("aria-expanded"));
                if (!expanded)
                    driver.ClickWhenAvailable(xpathSiteMapLauncherButton);
            }

            var dictionary = new Dictionary<string, IWebElement>();

            //Is this the sitemap with enableunifiedinterfaceshellrefresh?
            var xpathSitemapSwitcherButton = By.XPath(AppElements.Xpath[AppReference.Navigation.SitemapSwitcherButton]);
            success = driver.TryFindElement(xpathSitemapSwitcherButton, out IWebElement switcherButton);
            if (success)
            {
                switcherButton.Click(true);
                driver.WaitForTransaction();

                AddMenuItemsFrom(driver, AppReference.Navigation.SitemapSwitcherFlyout, dictionary);
            }

            var xpathSiteMapAreaMoreButton = By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapAreaMoreButton]);
            success = driver.TryFindElement(xpathSiteMapAreaMoreButton, out IWebElement moreButton);
            if (!success)
                return dictionary;

            bool isVisible = moreButton.IsVisible();
            if (isVisible)
            {
                moreButton.Click();
                AddMenuItemsFrom(driver, AppReference.Navigation.AreaMoreMenu, dictionary);
            }
            else
            {
                var singleItem = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapSingleArea].Replace("[NAME]", area)));
                dictionary.Add(singleItem.Text.ToLowerString(), singleItem);
            }

            return dictionary;
        }

        private static Dictionary<string, IWebElement> GetMenuItemsFrom(IWebDriver driver, string referenceToMenuItemsContainer)
        {
            var result = new Dictionary<string, IWebElement>();
            AddMenuItemsFrom(driver, referenceToMenuItemsContainer, result);
            return result;
        }

        private static void AddMenuItemsFrom(IWebDriver driver, string referenceToMenuItemsContainer, Dictionary<string, IWebElement> dictionary)
        {
            driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[referenceToMenuItemsContainer]),
                TimeSpan.FromSeconds(2),
                menu => AddMenuItems(menu, dictionary),
                "The Main Menu is not available."
            );
        }

        private static void AddMenuItems(IWebElement menu, Dictionary<string, IWebElement> dictionary)
        {
            var menuItems = menu.FindElements(By.TagName("li"));
            foreach (var item in menuItems)
            {
                string key = item.Text.ToLowerString();
                if (dictionary.ContainsKey(key))
                    continue;
                dictionary.Add(key, item);
            }
        }

        public static Dictionary<string, IWebElement> GetSubAreaMenuItems(IWebDriver driver)
        {
            var dictionary = new Dictionary<string, IWebElement>();

            //Sitemap without enableunifiedinterfaceshellrefresh
            var hasPinnedSitemapEntity = driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Navigation.PinnedSitemapEntity]));
            if (!hasPinnedSitemapEntity)
            {
                // Close SiteMap launcher since it is open
                var xpathToLauncherCloseButton = By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherCloseButton]);
                driver.ClickWhenAvailable(xpathToLauncherCloseButton);

                driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.SiteMapLauncherButton]));

                var menuContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.SubAreaContainer]));

                var subItems = menuContainer.FindElements(By.TagName("li"));

                foreach (var subItem in subItems)
                {
                    // Check 'Id' attribute, NULL value == Group Header
                    var id = subItem.GetAttribute("id");
                    if (string.IsNullOrEmpty(id))
                        continue;

                    // Filter out duplicate entity keys - click the first one in the list
                    var key = subItem.Text.ToLowerString();
                    if (!dictionary.ContainsKey(key))
                        dictionary.Add(key, subItem);
                }

                return dictionary;
            }

            //Sitemap with enableunifiedinterfaceshellrefresh enabled
            var menuShell = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.Navigation.SubAreaContainer]));

            //The menu is broke into multiple sections. Gather all items.
            foreach (IWebElement menuSection in menuShell)
            {
                var menuItems = menuSection.FindElements(By.XPath(AppElements.Xpath[AppReference.Navigation.SitemapMenuItems]));

                foreach (var menuItem in menuItems)
                {
                    var text = menuItem.Text.ToLowerString();
                    if (string.IsNullOrEmpty(text))
                        continue;

                    if (!dictionary.ContainsKey(text))
                        dictionary.Add(text, menuItem);
                }
            }

            return dictionary;
        }

        internal bool OpenSettingsOption(string command, string dataId, int thinkTime = Constants.DefaultThinkTime)
        {
            var xpathFlyout = By.XPath(AppElements.Xpath[AppReference.Navigation.SettingsLauncher].Replace("[NAME]", command));
            var xpathToFlyoutButton = By.XPath(AppElements.Xpath[AppReference.Navigation.SettingsLauncherBar].Replace("[NAME]", command));

            IWebElement flyout;
            bool success = driver.TryFindElement(xpathFlyout, out flyout);
            if (!success || !flyout.Displayed)
            {
                driver.ClickWhenAvailable(xpathToFlyoutButton, $"No command button exists that match with: {command}.");
                flyout = driver.WaitUntilVisible(xpathFlyout, "Flyout menu did not became visible");
            }

            var menuItems = flyout.FindElements(By.TagName("button"));
            var button = menuItems.FirstOrDefault(x => x.GetAttribute("data-id").Contains(dataId));
            if (button != null)
            {
                button.Click();
                return true;
            }

            throw new InvalidOperationException($"No command with data-id: {dataId} exists inside of the command menu {command}");
        }

        /// <summary>
        /// Opens the Guided Help
        /// </summary>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        /// <example>xrmBrowser.Navigation.OpenGuidedHelp();</example>
        public bool OpenGuidedHelp(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.GuidedHelp]));

            return true;
        }

        /// <summary>
        /// Opens the Admin Portal
        /// </summary>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        /// <example>xrmBrowser.Navigation.OpenAdminPortal();</example>
        internal bool OpenAdminPortal(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Application.Shell]));
            driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.AdminPortal]))?.Click();
            driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.AdminPortalButton]))?.Click();
            return true;
        }

        /// <summary>
        /// Open Global Search
        /// </summary>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        /// <example>xrmBrowser.Navigation.OpenGlobalSearch();</example>
        internal bool OpenGlobalSearch(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitUntilClickable(By.XPath(AppElements.Xpath[AppReference.Navigation.SearchButton]),
                TimeSpan.FromSeconds(5),
                d => { driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.SearchButton])); },
                "The Global Search button is not available."
            );
            return true;
        }

        internal bool ClickQuickLaunchButton(string toolTip, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitUntilClickable(By.XPath(AppElements.Xpath[AppReference.Navigation.QuickLaunchMenu]));

            //Text could be in the crumb bar.  Find the Quick launch bar buttons and click that one.
            var buttons = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.QuickLaunchMenu]));
            var launchButton = buttons.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.QuickLaunchButton].Replace("[NAME]", toolTip)));
            launchButton.Click();

            return true;
        }

        internal bool QuickCreate(string entityName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            //Click the + button in the ribbon
            var quickCreateButton = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.QuickCreateButton]));
            quickCreateButton.Click(true);

            //Find the entity name in the list
            var entityMenuList = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Navigation.QuickCreateMenuList]));
            var entityMenuItems = entityMenuList.FindElements(By.XPath(AppElements.Xpath[AppReference.Navigation.QuickCreateMenuItems]));
            var entitybutton = entityMenuItems.FirstOrDefault(e => e.Text.Contains(entityName, StringComparison.OrdinalIgnoreCase));

            if (entitybutton == null)
                throw new Exception(String.Format("{0} not found in Quick Create list.", entityName));

            //Click the entity name
            entitybutton.Click(true);

            driver.WaitForTransaction();

            return true;
        }

        public bool GoBack()
        {
            driver.WaitForTransaction();

            var element = driver.ClickWhenAvailable(By.XPath(Elements.Xpath[Reference.Navigation.GoBack]));

            driver.WaitForTransaction();
            return element != null;
        }

        #endregion

        #region Dialogs

        internal bool SwitchToDialog(int frameIndex = 0)
        {
            var index = "";
            if (frameIndex > 0)
                index = frameIndex.ToString();

            driver.SwitchTo().DefaultContent();

            // Check to see if dialog is InlineDialog or popup
            var inlineDialog = driver.HasElement(By.XPath(Elements.Xpath[Reference.Frames.DialogFrame].Replace("[INDEX]", index)));
            if (inlineDialog)
            {
                //wait for the content panel to render
                driver.WaitUntilAvailable(By.XPath(Elements.Xpath[Reference.Frames.DialogFrame].Replace("[INDEX]", index)),
                    TimeSpan.FromSeconds(2),
                    d => { driver.SwitchTo().Frame(Elements.ElementId[Reference.Frames.DialogFrameId].Replace("[INDEX]", index)); });
                return true;
            }
            else
            {
                // need to add this functionality
                //SwitchToPopup();
            }

            return true;
        }

        internal bool CloseWarningDialog()
        {
            var inlineDialog = this.SwitchToDialog();
            if (inlineDialog)
            {
                var dialogFooter = driver.WaitUntilAvailable(By.XPath(Elements.Xpath[Reference.Dialogs.WarningFooter]));

                if (
                    !(dialogFooter?.FindElements(By.XPath(Elements.Xpath[Reference.Dialogs.WarningCloseButton])).Count >
                      0)) return true;
                var closeBtn = dialogFooter.FindElement(By.XPath(Elements.Xpath[Reference.Dialogs.WarningCloseButton]));
                closeBtn.Click();
            }

            return true;
        }

        internal bool ConfirmationDialog(bool ClickConfirmButton)
        {
            //Passing true clicks the confirm button.  Passing false clicks the Cancel button.
            var inlineDialog = this.SwitchToDialog();
            if (inlineDialog)
            {
                //Wait until the buttons are available to click
                var dialogFooter = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.ConfirmButton]));

                if (
                    !(dialogFooter?.FindElements(By.XPath(AppElements.Xpath[AppReference.Dialogs.ConfirmButton])).Count >
                      0)) return true;

                //Click the Confirm or Cancel button
                IWebElement buttonToClick;
                if (ClickConfirmButton)
                    buttonToClick = dialogFooter.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.ConfirmButton]));
                else
                    buttonToClick = dialogFooter.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.CancelButton]));

                buttonToClick.Click();
            }

            return true;
        }

        internal bool DuplicateDetection(bool clickSaveOrCancel)
        {
            string operationType;

            if (clickSaveOrCancel)
            {
                operationType = "Ignore and Save";
            }
            else
                operationType = "Cancel";

            //Passing true clicks the Ignore and Save button.  Passing false clicks the Cancel button.
            var inlineDialog = this.SwitchToDialog();
            if (inlineDialog)
            {
                //Wait until the buttons are available to click
                var dialogFooter = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DuplicateDetectionIgnoreSaveButton]));

                if (
                    !(dialogFooter?.FindElements(By.XPath(AppElements.Xpath[AppReference.Dialogs.DuplicateDetectionIgnoreSaveButton])).Count >
                      0)) return true;

                //Click the Confirm or Cancel button
                IWebElement buttonToClick;
                if (clickSaveOrCancel)
                    buttonToClick = dialogFooter.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.DuplicateDetectionIgnoreSaveButton]));
                else
                    buttonToClick = dialogFooter.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.DuplicateDetectionCancelButton]));

                buttonToClick.Click();
            }

            if (clickSaveOrCancel)
            {
                // Wait for Save before proceeding
                driver.WaitForTransaction();
            }

            return true;
        }

        internal bool SetStateDialog(bool clickOkButton)
        {
            //Passing true clicks the Activate/Deactivate button.  Passing false clicks the Cancel button.
            var inlineDialog = this.SwitchToDialog();
            if (inlineDialog)
            {
                //Wait until the buttons are available to click
                var dialog = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.SetStateDialog]));

                if (
                    !(dialog?.FindElements(By.TagName("button")).Count >
                      0)) return true;

                //Click the Activate/Deactivate or Cancel button
                IWebElement buttonToClick;
                if (clickOkButton)
                    buttonToClick = dialog.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.SetStateActionButton]));
                else
                    buttonToClick = dialog.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.SetStateCancelButton]));

                buttonToClick.Click();
            }

            return true;
        }

        internal bool PublishDialog(bool ClickConfirmButton)
        {
            //Passing true clicks the confirm button.  Passing false clicks the Cancel button.

            var inlineDialog = this.SwitchToDialog();
            if (inlineDialog)
            {
                //Wait until the buttons are available to click
                var dialogFooter = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.PublishConfirmButton]));

                if (
                    !(dialogFooter?.FindElements(By.XPath(AppElements.Xpath[AppReference.Dialogs.PublishConfirmButton])).Count >
                      0)) return true;

                //Click the Confirm or Cancel button
                IWebElement buttonToClick;
                if (ClickConfirmButton)
                    buttonToClick = dialogFooter.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.PublishConfirmButton]));
                else
                    buttonToClick = dialogFooter.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.PublishCancelButton]));

                buttonToClick.Click();
            }

            return true;
        }


        internal bool AssignDialog(Dialogs.AssignTo to, string userOrTeamName = null)
        {
            var inlineDialog = this.SwitchToDialog();
            if (!inlineDialog)
                return false;

            if (to == Dialogs.AssignTo.Me)
            {
                SetValue(new OptionSet { Name = Elements.ElementId[Reference.Dialogs.Assign.AssignToId], Value = "Me" }, FormContextType.Dialog);
            }
            else
            {
                SetValue(new OptionSet { Name = Elements.ElementId[Reference.Dialogs.Assign.AssignToId], Value = "User or team" }, FormContextType.Dialog);

                //Set the User Or Team
                var userOrTeamField = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldLookup]), "User field unavailable");
                var input = userOrTeamField.ClickWhenAvailable(By.TagName("input"), "User field unavailable");
                input.SendKeys(userOrTeamName, true);

                ThinkTime(2000);

                //Pick the User from the list
                var container = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Dialogs.AssignDialogUserTeamLookupResults]));
                container.WaitUntil(
                    c => c.FindElements(By.TagName("li")).FirstOrDefault(r => r.Text.StartsWith(userOrTeamName, StringComparison.OrdinalIgnoreCase)),
                    successCallback: e => e.Click(true),
                    failureCallback: () => throw new InvalidOperationException($"None {to} found which match with '{userOrTeamName}'"));
            }

            //Click Assign
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.AssignDialogOKButton]), TimeSpan.FromSeconds(5),
                "Unable to click the OK button in the assign dialog");

            return true;
        }

        internal bool SwitchProcessDialog(string processToSwitchTo)
        {

            //Wait for the Grid to load
            driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Dialogs.ActiveProcessGridControlContainer]));

            //Select the Process
            var popup = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.SwitchProcessContainer]));
            var labels = popup.FindElements(By.TagName("label"));
            foreach (var label in labels)
            {
                if (label.Text.Equals(processToSwitchTo, StringComparison.OrdinalIgnoreCase))
                {
                    label.Click();
                    break;
                }
            }

            //Click the OK button
            var okBtn = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.SwitchProcessDialogOK]));
            okBtn.Click();

            return true;

        }

        internal bool CloseOpportunityDialog(bool clickOK)
        {

            var inlineDialog = this.SwitchToDialog();

            if (inlineDialog)
            {
                //Close Opportunity
                var xPath = AppElements.Xpath[AppReference.Dialogs.CloseOpportunity.Ok];

                //Cancel
                if (!clickOK)
                    xPath = AppElements.Xpath[AppReference.Dialogs.CloseOpportunity.Ok];

                driver.ClickWhenAvailable(By.XPath(xPath), TimeSpan.FromSeconds(5), "The Close Opportunity dialog is not available.");
            }

            return true;
        }

        internal bool HandleSaveDialog()
        {
            //If you click save and something happens, handle it.  Duplicate Detection/Errors/etc...
            //Check for Dialog and figure out which type it is and return the dialog type.

            //Introduce think time to avoid timing issues on save dialog
            ThinkTime(1000);
            //Is it Duplicate Detection?
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.DuplicateDetectionWindowMarker])))
            {
                if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.DuplicateDetectionGridRows])))
                {
                    //Select the first record in the grid
                    driver.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.DuplicateDetectionGridRows]))[0].Click(true);

                    //Click Ignore and Save
                    driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.DuplicateDetectionIgnoreAndSaveButton])).Click(true);
                    driver.WaitForTransaction();
                }
            }

            //Is it an Error?
            if (driver.HasElement(By.XPath("//div[contains(@data-id,'errorDialogdialog')]")))
            {
                var errorDialog = driver.FindElement(By.XPath("//div[contains(@data-id,'errorDialogdialog')]"));

                var errorDetails = errorDialog.FindElement(By.XPath(".//*[contains(@data-id,'errorDialog_subtitle')]"));

                if (!String.IsNullOrEmpty(errorDetails.Text))
                    throw new InvalidOperationException(errorDetails.Text);
            }


            return true;
        }

        internal string GetBusinessProcessErrorText(int waitTimeInSeconds)
        {

            string errorDetails = string.Empty;
            var errorDialog = driver.WaitUntilAvailable(By.XPath("//div[contains(@data-id,'errorDialogdialog')]"), new TimeSpan(0, 0, waitTimeInSeconds));

            // Is error dialog present?
            if (errorDialog != null)
            {
                var errorDetailsElement = errorDialog.FindElement(By.XPath(".//*[contains(@data-id,'errorDialog_subtitle')]"));

                if (errorDetailsElement != null)
                {
                    if (!String.IsNullOrEmpty(errorDetailsElement.Text))
                        errorDetails = errorDetailsElement.Text;
                }
            }

            return errorDetails;
        }

        private static ICollection<IWebElement> GetListItems(IWebElement container, LookupItem control)
        {
            var name = control.Name;
            var xpathToItems = By.XPath(AppElements.Xpath[AppReference.Entity.LookupFieldResultListItem].Replace("[NAME]", name));

            //wait for complete the search
            container.WaitUntil(d => d.FindVisible(xpathToItems)?.Text?.Contains(control.Value, StringComparison.OrdinalIgnoreCase) == true);

            ICollection<IWebElement> result = container.WaitUntil(
                d => d.FindElements(xpathToItems),
                failureCallback: () => throw new InvalidOperationException($"No Results Matching {control.Value} Were Found.")
                );
            return result;
        }
        #endregion

        #region CommandBar

        internal bool ClickCommand(string name, string subname = null, string subSecondName = null, int thinkTime = Constants.DefaultThinkTime)
        {

            // Find the button in the CommandBar
            IWebElement ribbon;
            // Checking if any dialog is active
            if (driver.HasElement(By.XPath(string.Format(AppElements.Xpath[AppReference.Dialogs.DialogContext]))))
            {
                var dialogContainer = driver.FindElement(By.XPath(string.Format(AppElements.Xpath[AppReference.Dialogs.DialogContext])));
                ribbon = dialogContainer.WaitUntilAvailable(By.XPath(string.Format(AppElements.Xpath[AppReference.CommandBar.Container])));
            }
            else
            {
                ribbon = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.CommandBar.Container]));
            }


            if (ribbon == null)
            {
                ribbon = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.CommandBar.ContainerGrid]),
                    TimeSpan.FromSeconds(5),
                    "Unable to find the ribbon.");
            }

            //Is the button in the ribbon?
            if (ribbon.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCommandLabel].Replace("[NAME]", name)), out var command))
            {
                command.Click(true);
                driver.WaitForTransaction();
            }
            else
            {
                //Is the button in More Commands?
                if (ribbon.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCommandLabel].Replace("[NAME]", "More Commands")), out var moreCommands))
                {
                    // Click More Commands
                    moreCommands.Click(true);
                    driver.WaitForTransaction();

                    //Click the button
                    if (ribbon.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowButton].Replace("[NAME]", name)), out var overflowCommand))
                    {
                        overflowCommand.Click(true);
                        driver.WaitForTransaction();
                    }
                    else
                        throw new InvalidOperationException($"No command with the name '{name}' exists inside of Commandbar.");
                }
                else
                    throw new InvalidOperationException($"No command with the name '{name}' exists inside of Commandbar.");
            }

            if (!string.IsNullOrEmpty(subname))
            {
                var submenu = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.CommandBar.MoreCommandsMenu]));

                submenu.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowButton].Replace("[NAME]", subname)), out var subbutton);

                if (subbutton != null)
                {
                    subbutton.Click(true);
                }
                else
                    throw new InvalidOperationException($"No sub command with the name '{subname}' exists inside of Commandbar.");

                if (!string.IsNullOrEmpty(subSecondName))
                {
                    var subSecondmenu = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.CommandBar.MoreCommandsMenu]));

                    subSecondmenu.TryFindElement(
                        By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowButton]
                            .Replace("[NAME]", subSecondName)), out var subSecondbutton);

                    if (subSecondbutton != null)
                    {
                        subSecondbutton.Click(true);
                    }
                    else
                        throw new InvalidOperationException($"No sub command with the name '{subSecondName}' exists inside of Commandbar.");
                }
            }

            driver.WaitForTransaction();

            return true;
        }


        /// <summary>
        /// Returns the values of CommandBar objects
        /// </summary>
        /// <param name="includeMoreCommandsValues">Whether or not to check the more commands overflow list</param>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        /// <example>xrmApp.CommandBar.GetCommandValues();</example>
        internal List<string> GetCommandValues(bool includeMoreCommandsValues = false, int Time = Constants.DefaultThinkTime)
        {
            ThinkTime(Time);
            return TryGetCommandValues(includeMoreCommandsValues, driver);
        }

        private static List<string> TryGetCommandValues(bool includeMoreCommandsValues, IWebDriver driver)
        {
            const string moreCommandsLabel = "more commands";

            //Find the button in the CommandBar
            IWebElement ribbon = GetRibbon(driver);

            //Get the CommandBar buttons
            Dictionary<string, IWebElement> commandBarItems = GetMenuItems(ribbon);
            bool hasMoreCommands = commandBarItems.TryGetValue(moreCommandsLabel, out var moreCommandsButton);
            if (includeMoreCommandsValues && hasMoreCommands)
            {
                moreCommandsButton.Click(true);

                driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.CommandBar.MoreCommandsMenu]),
                    menu => AddMenuItems(menu, commandBarItems),
                    "Unable to locate the 'More Commands' menu"
                    );
            }

            var result = GetCommandNames(commandBarItems.Values);
            return result;
        }

        private static Dictionary<string, IWebElement> GetMenuItems(IWebElement menu)
        {
            var result = new Dictionary<string, IWebElement>();
            AddMenuItems(menu, result);
            return result;
        }

        private static List<string> GetCommandNames(IEnumerable<IWebElement> commandBarItems)
        {
            var result = new List<string>();
            foreach (var value in commandBarItems)
            {
                string commandText = value.Text.Trim();
                if (string.IsNullOrWhiteSpace(commandText))
                    continue;

                if (commandText.Contains("\r\n"))
                {
                    commandText = commandText.Substring(0, commandText.IndexOf("\r\n", StringComparison.Ordinal));
                }
                result.Add(commandText);
            }
            return result;
        }

        private static IWebElement GetRibbon(IWebDriver driver)
        {
            var xpathCommandBarContainer = By.XPath(AppElements.Xpath[AppReference.CommandBar.Container]);
            var xpathCommandBarGrid = By.XPath(AppElements.Xpath[AppReference.CommandBar.ContainerGrid]);

            IWebElement ribbon =
                driver.WaitUntilAvailable(xpathCommandBarContainer, 5.Seconds()) ??
                driver.WaitUntilAvailable(xpathCommandBarGrid, 5.Seconds()) ??
                throw new InvalidOperationException("Unable to find the ribbon.");

            return ribbon;
        }

        #endregion

        #region Grid

        public Dictionary<string, IWebElement> OpenViewPicker(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.ViewSelector]),
                TimeSpan.FromSeconds(20),
                "Unable to click the View Picker"
            );

            var viewContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.ViewContainer]));
            var viewItems = viewContainer.FindElements(By.TagName("li"));

            var result = new Dictionary<string, IWebElement>();
            foreach (var viewItem in viewItems)
            {
                var role = viewItem.GetAttribute("role");
                if (role != "option")
                    continue;

                var key = viewItem.Text.ToLowerString();
                if (string.IsNullOrWhiteSpace(key))
                    continue;

                if (!result.ContainsKey(key))
                    result.Add(key, viewItem);
            }
            return result;
        }

        internal bool SwitchView(string viewName, string subViewName = null, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var views = OpenViewPicker();
            Thread.Sleep(500);
            var key = viewName.ToLowerString();
            bool success = views.TryGetValue(key, out var view);
            if (!success)
                throw new InvalidOperationException($"No view with the name '{key}' exists.");

            view.Click(true);
            if (subViewName != null)
            {
                // TBD
            }
            driver.WaitForTransaction();
            return true;
        }

        internal bool SwitchSubGridView(string subGridName, string viewName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            // Initialize required variables
            IWebElement viewPicker = null;

            // Find the SubGrid
            var subGrid = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridContents].Replace("[NAME]", subGridName)));

            var foundPicker = subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridViewPickerButton]), out viewPicker);

            if (foundPicker)
            {
                viewPicker.Click(true);

                // Locate the ViewSelector flyout
                var viewPickerFlyout = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridViewPickerFlyout]), new TimeSpan(0, 0, 2));

                var viewItems = viewPickerFlyout.FindElements(By.TagName("li"));


                //Is the button in the ribbon?
                if (viewItems.Any(x => x.GetAttribute("aria-label").Equals(viewName, StringComparison.OrdinalIgnoreCase)))
                {
                    viewItems.FirstOrDefault(x => x.GetAttribute("aria-label").Equals(viewName, StringComparison.OrdinalIgnoreCase)).Click(true);
                }

            }
            else
                throw new NotFoundException($"Unable to locate the viewPicker for SubGrid {subGridName}");

            driver.WaitForTransaction();

            return true;
        }

        internal bool OpenRecord(int index, int thinkTime = Constants.DefaultThinkTime, bool checkRecord = false)
        {
            ThinkTime(thinkTime);
            var xpathToGrid = By.XPath(AppElements.Xpath[AppReference.Grid.Container]);
            IWebElement control = driver.WaitUntilAvailable(xpathToGrid);

            Func<Actions, Actions> action;
            if (checkRecord)
                action = e => e.Click();
            else
                action = e => e.DoubleClick();

            var xpathToCell = By.XPath($".//div[@data-id='cell-{index}-1']");
            control.WaitUntilClickable(xpathToCell,
                cell =>
                {
                    var emptyDiv = cell.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.RowsContainerCheckbox]));
                    driver.Perform(action, cell, cell.LeftTo(emptyDiv));
                },
                $"An error occur trying to open the record at position {index}"
            );

            driver.WaitForTransaction();
            return true;
        }

        internal bool Search(string searchCriteria, bool clearByDefault = true, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            driver.WaitUntilClickable(By.XPath(AppElements.Xpath[AppReference.Grid.QuickFind]));

            if (clearByDefault)
            {
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.QuickFind])).Clear();
            }

            driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.QuickFind])).SendKeys(searchCriteria);
            driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.QuickFind])).SendKeys(OpenQA.Selenium.Keys.Enter);

            //driver.WaitForTransaction();

            return true;
        }

        internal bool ClearSearch(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitUntilClickable(By.XPath(AppElements.Xpath[AppReference.Grid.QuickFind]));

            driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.QuickFind])).Clear();

            return true;
        }

        internal List<GridItem> GetGridItems(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var returnList = new List<GridItem>();

            driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.Container]));

            var rows = driver.FindElements(By.ClassName("wj-row"));
            var columnGroup = driver.FindElement(By.ClassName("wj-colheaders"));

            foreach (var row in rows)
            {
                if (!string.IsNullOrEmpty(row.GetAttribute("data-lp-id")) && !string.IsNullOrEmpty(row.GetAttribute("role")))
                {
                    //MscrmControls.Grid.ReadOnlyGrid|entity_control|account|00000000-0000-0000-00aa-000010001001|account|cc-grid|grid-cell-container
                    var datalpid = row.GetAttribute("data-lp-id").Split('|');
                    var cells = row.FindElements(By.ClassName("wj-cell"));
                    var currentindex = 0;
                    var link =
                        $"{new Uri(driver.Url).Scheme}://{new Uri(driver.Url).Authority}/main.aspx?etn={datalpid[2]}&pagetype=entityrecord&id=%7B{datalpid[3]}%7D";

                    var item = new GridItem
                    {
                        EntityName = datalpid[2],
                        Url = new Uri(link)
                    };

                    foreach (var column in columnGroup.FindElements(By.ClassName("wj-row")))
                    {
                        var rowHeaders = column.FindElements(By.TagName("div"))
                            .Where(c => !string.IsNullOrEmpty(c.GetAttribute("title")) && !string.IsNullOrEmpty(c.GetAttribute("id")));

                        foreach (var header in rowHeaders)
                        {
                            var id = header.GetAttribute("data-id") ?? header.GetAttribute("id");
                            var className = header.GetAttribute("class");
                            var cellData = cells[currentindex + 1].GetAttribute("title");

                            if (!string.IsNullOrEmpty(id)
                                && className.Contains("wj-cell")
                                && !string.IsNullOrEmpty(cellData)
                                && !id.Contains("btnheaderselectcolumn")
                                && cells.Count > currentindex
                            )
                            {
                                item[id] = cellData.Replace("-", "");
                                currentindex++;
                            }

                        }

                        returnList.Add(item);
                    }
                }
            }

            return returnList;
        }

        internal bool NextPage(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.NextPage]));

            driver.WaitForTransaction();

            return true;
        }

        internal bool PreviousPage(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.PreviousPage]));

            driver.WaitForTransaction();

            return true;
        }

        internal bool FirstPage(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.FirstPage]));

            driver.WaitForTransaction();

            return true;
        }

        internal bool SelectAll(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.SelectAll]));

            driver.WaitForTransaction();

            return true;
        }

        public bool ShowChart(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Grid.ShowChart])))
            {
                driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.ShowChart]));

                driver.WaitForTransaction();
            }
            else
            {
                throw new Exception("The Show Chart button does not exist.");
            }

            return true;
        }

        public bool HideChart(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Grid.HideChart])))
            {
                driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.HideChart]));

                driver.WaitForTransaction();
            }
            else
            {
                throw new Exception("The Hide Chart button does not exist.");
            }

            return true;
        }

        public bool FilterByLetter(char filter, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            if (!Char.IsLetter(filter) && filter != '#')
                throw new InvalidOperationException("Filter criteria is not valid.");
            var jumpBar = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.JumpBar]));
            var link = jumpBar.FindElement(By.Id(filter + "_link"));

            if (link != null)
            {
                link.Click();

                driver.WaitForTransaction();
            }
            else
            {
                throw new Exception($"Filter with letter: {filter} link does not exist");
            }

            return true;

        }

        public bool FilterByAll(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            var jumpBar = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.JumpBar]));
            var link = jumpBar.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.FilterByAll]));

            if (link != null)
            {
                link.Click();

                driver.WaitForTransaction();
            }
            else
            {
                throw new Exception($"Filter by All link does not exist");
            }

            return true;
        }

        public bool SelectRecord(int index, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var container = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.RowsContainer]), "Grid Container does not exist.");

            var row = container.FindElement(By.Id("id-cell-" + index + "-1"));
            if (row == null)
                throw new Exception($"Row with index: {index} does not exist.");

            row.Click();
            return true;
        }

        public bool SwitchChart(string chartName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            if (!driver.IsVisible(By.XPath(AppElements.Xpath[AppReference.Grid.ChartSelector])))
                ShowChart();

            ThinkTime(1000);

            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Grid.ChartSelector]));

            var list = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.ChartViewList]));

            driver.ClickWhenAvailable(By.XPath("//li[contains(@title,'" + chartName + "')]"));

            return true;

        }

        public bool Sort(string columnName, string sortOptionButtonText, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);


            var sortCol = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.GridSortColumn].Replace("[COLNAME]", columnName)));

            if (sortCol == null)
                throw new InvalidOperationException($"Column: {columnName} Does not exist");
            else
            {
                sortCol.Click(true);
                driver.WaitUntilClickable(By.XPath($@"//button[@name='{sortOptionButtonText}']")).Click(true);
            }

            driver.WaitForTransaction();
            return true;

        }

        #endregion

        #region RelatedGrid

        /// <summary>
        /// Opens the grid record.
        /// </summary>
        /// <param name="index">The index.</param>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        public bool OpenRelatedGridRow(int index, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            var grid = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.Container]));
            var gridCellContainer = grid.FindElement(By.XPath(AppElements.Xpath[AppReference.Grid.CellContainer]));
            var rowCount = gridCellContainer.GetAttribute("data-row-count");
            var count = 0;

            if (rowCount == null || !int.TryParse(rowCount, out count) || count <= 0) return true;
            var link =
                gridCellContainer.FindElement(
                    By.XPath("//div[@role='gridcell'][@header-row-number='" + index + "']/following::div"));

            if (link == null)
                throw new InvalidOperationException($"No record with the index '{index}' exists.");

            link.Click();
 ;

            driver.WaitForTransaction();
            return true;
        }

        public bool ClickRelatedCommand(string name, string subName = null, string subSecondName = null)
        {

            // Locate Related Command Bar Button List
            var relatedCommandBarButtonList = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarButtonList]));

            // Validate list has provided command bar button
            if (relatedCommandBarButtonList.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarButton].Replace("[NAME]", name))))
            {
                relatedCommandBarButtonList.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarButton].Replace("[NAME]", name))).Click(true);

                driver.WaitForTransaction();

                if (subName != null)
                {
                    //Look for Overflow flyout
                    if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer])))
                    {
                        var overFlowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer]));

                        if (!overFlowContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))))
                            throw new NotFoundException($"{subName} button not found");

                        overFlowContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))).Click(true);

                        driver.WaitForTransaction();
                    }

                    if (subSecondName != null)
                    {
                        //Look for Overflow flyout
                        if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer])))
                        {
                            var overFlowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer]));

                            if (!overFlowContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))))
                                throw new NotFoundException($"{subName} button not found");

                            overFlowContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))).Click(true);

                            driver.WaitForTransaction();
                        }
                    }
                }

                return true;
            }
            else
            {
                // Button was not found, check if we should be looking under More Commands (OverflowButton)
                var moreCommands = relatedCommandBarButtonList.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowButton]));

                if (moreCommands)
                {
                    var overFlowButton = relatedCommandBarButtonList.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowButton]));
                    overFlowButton.Click(true);

                    if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer]))) //Look for Overflow
                    {
                        var overFlowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer]));

                        if (overFlowContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarButton].Replace("[NAME]", name))))
                        {
                            overFlowContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarButton].Replace("[NAME]", name))).Click(true);

                            driver.WaitForTransaction();

                            if (subName != null)
                            {
                                overFlowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer]));

                                if (!overFlowContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))))
                                    throw new NotFoundException($"{subName} button not found");

                                overFlowContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))).Click(true);

                                driver.WaitForTransaction();

                                if (subSecondName != null)
                                {
                                    overFlowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarOverflowContainer]));

                                    if (!overFlowContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))))
                                        throw new NotFoundException($"{subName} button not found");

                                    overFlowContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Related.CommandBarSubButton].Replace("[NAME]", subName))).Click(true);

                                    driver.WaitForTransaction();
                                }
                            }

                            return true;
                        }
                    }
                    else
                    {
                        throw new NotFoundException($"{name} button not found in the More Commands container. Button names are case sensitive. Please check for proper casing of button name.");
                    }

                }
                else
                {
                    throw new NotFoundException($"{name} button not found. Button names are case sensitive. Please check for proper casing of button name.");
                }
            }

            return true;
        }

        #endregion

        #region Subgrid

        /// This method is obsolete. Do not use.
        public bool ClickSubgridAddButton(string subgridName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridAddButton].Replace("[NAME]", subgridName)))?.Click();

            return true;
        }

        public bool ClickSubGridCommand(string subGridName, string name, string subName = null, string subSecondName = null)
        {
            // Initialize required local variables
            IWebElement subGridCommandBar = null;

            // Find the SubGrid
            var subGrid = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridContents].Replace("[NAME]", subGridName)));

            if (subGrid == null)
                throw new NotFoundException($"Unable to locate subgrid contents for {subGridName} subgrid.");

            // Check if grid commandBar was found
            if (subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCommandBar].Replace("[NAME]", subGridName)), out subGridCommandBar))
            {
                //Is the button in the ribbon?
                if (subGridCommandBar.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCommandLabel].Replace("[NAME]", name)), out var command))
                {
                    command.Click(true);
                    driver.WaitForTransaction();
                }
                else
                {
                    // Is the button in More Commands overflow?
                    if (subGridCommandBar.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCommandLabel].Replace("[NAME]", "More Commands")), out var moreCommands))
                    {
                        // Click More Commands
                        moreCommands.Click(true);
                        driver.WaitForTransaction();

                        // Locate the overflow button (More Commands flyout)
                        var overflowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowContainer]));

                        //Click the primary button, if found
                        if (overflowContainer.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowButton].Replace("[NAME]", name)), out var overflowCommand))
                        {
                            overflowCommand.Click(true);
                            driver.WaitForTransaction();
                        }
                        else
                            throw new InvalidOperationException($"No command with the name '{name}' exists inside of {subGridName} Commandbar.");
                    }
                    else
                        throw new InvalidOperationException($"No command with the name '{name}' exists inside of {subGridName} CommandBar.");
                }

                if (subName != null)
                {
                    // Locate the sub-button flyout if subName present
                    var overflowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowContainer]));

                    //Click the primary button, if found
                    if (overflowContainer.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowButton].Replace("[NAME]", subName)), out var overflowButton))
                    {
                        overflowButton.Click(true);
                        driver.WaitForTransaction();
                    }
                    else
                        throw new InvalidOperationException($"No command with the name '{subName}' exists under the {name} command inside of {subGridName} Commandbar.");

                    // Check if we need to go to a 3rd level
                    if (subSecondName != null)
                    {
                        // Locate the sub-button flyout if subSecondName present
                        overflowContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowContainer]));

                        //Click the primary button, if found
                        if (overflowContainer.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridOverflowButton].Replace("[NAME]", subSecondName)), out var secondOverflowCommand))
                        {
                            secondOverflowCommand.Click(true);
                            driver.WaitForTransaction();
                        }
                        else
                            throw new InvalidOperationException($"No command with the name '{subSecondName}' exists under the {subName} command inside of {name} on the {subGridName} SubGrid Commandbar.");
                    }
                }
            }
            else
                throw new InvalidOperationException($"Unable to locate the Commandbar for the {subGrid} SubGrid.");

            return true;
        }

        internal bool ClickSubgridSelectAll(string subGridName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            // Find the SubGrid
            var subGrid = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridContents].Replace("[NAME]", subGridName)));

            if (subGrid != null)
            {
                var subGridButtons = subGrid.FindElements(By.TagName("button"));

                //Is the button in the ribbon?
                if (subGridButtons.Any(x => x.GetAttribute("title").Equals("Select All", StringComparison.OrdinalIgnoreCase)))
                {
                    subGridButtons.FirstOrDefault(x => x.GetAttribute("title").Equals("Select All", StringComparison.OrdinalIgnoreCase)).Click(true);
                    driver.WaitForTransaction();
                }
                else
                    throw new NotFoundException("Select All button not found. Please make sure the grid is displayed. Card layout is not supported for Select All.");
            }
            else
                throw new NotFoundException($"Unable to locate subgrid with name {subGridName}");


            return true;
        }

        internal bool SearchSubGrid(string subGridName, string searchCriteria, bool clearByDefault = false)
        {
            IWebElement subGridSearchField = null;
            // Find the SubGrid
            var subGrid = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridContents].Replace("[NAME]", subGridName)));
            if (subGrid != null)
            {
                var foundSearchField = subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridSearchBox]), out subGridSearchField);
                if (foundSearchField)
                {
                    var inputElement = subGridSearchField.FindElement(By.TagName("input"));

                    if (clearByDefault)
                    {
                        inputElement.Clear();
                    }

                    inputElement.SendKeys(searchCriteria);

                    var startSearch = subGridSearchField.FindElement(By.TagName("button"));
                    startSearch.Click(true);

                    driver.WaitForTransaction();
                }
                else
                    throw new NotFoundException($"Unable to locate the search box for subgrid {subGridName}. Please validate that view search is enabled for this subgrid");
            }
            else
                throw new NotFoundException($"Unable to locate subgrid with name {subGridName}");

            return true;
        }

        #endregion

        #region Entity

        internal bool CancelQuickCreate(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var save = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.CancelButton]),
                "Quick Create Cancel Button is not available");
            save?.Click(true);

            driver.WaitForTransaction();

            return true;
        }

        /// <summary>
        /// Open Entity
        /// </summary>
        /// <param name="entityName">The entity name</param>
        /// <param name="id">The Id</param>
        /// <param name="thinkTime">The think time</param>
        internal bool OpenEntity(string entityName, Guid id, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            //https:///main.aspx?appid=98d1cf55-fc47-e911-a97c-000d3ae05a70&pagetype=entityrecord&etn=lead&id=ed975ea3-531c-e511-80d8-3863bb3ce2c8
            var uri = new Uri(this.driver.Url);
            var qs = HttpUtility.ParseQueryString(uri.Query.ToLower());
            var appId = qs.Get("appid");
            var link = $"{uri.Scheme}://{uri.Authority}/main.aspx?appid={appId}&etn={entityName}&pagetype=entityrecord&id={id}";

            if (Convert.ToBoolean(GetValueFromConfig("UCITestMode")))
            {
                link += "&flags=testmode=true";
            }
            if (Convert.ToBoolean(GetValueFromConfig("UCIPerformanceMode")))
            {
                link += "&perf=true";
            }

            driver.Navigate().GoToUrl(link);

            //SwitchToContent();
            driver.WaitForPageToLoad();
            driver.WaitForTransaction();
            driver.WaitUntilClickable(By.XPath(Elements.Xpath[Reference.Entity.Form]),
                TimeSpan.FromSeconds(30),
                "CRM Record is Unavailable or not finished loading. Timeout Exceeded"
            );

            return true;
        }

        /// <summary>
        /// Saves the entity
        /// </summary>
        /// <param name="thinkTime"></param>
        internal bool Save(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var save = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.Save]),
                "Save Buttton is not available");

            save?.Click();

            return true;
        }

        internal bool SaveQuickCreate(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var save = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.SaveAndCloseButton]),
                "Quick Create Save Button is not available");
            save?.Click(true);

            driver.WaitForTransaction();

            return true;
        }

        /// <summary>
        /// Open record set and navigate record index.
        /// This method supersedes Navigate Up and Navigate Down outside of UCI 
        /// </summary>
        /// <param name="index">The index.</param>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        /// <example>xrmBrowser.Entity.OpenRecordSetNavigator();</example>
        public bool OpenRecordSetNavigator(int index = 0, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            // check if record set navigator parent div is set to open
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.RecordSetNavigatorOpen])))
            {
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.RecordSetNavigator])).Click();
            }

            var navList = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.RecordSetNavList]));
            var links = navList.FindElements(By.TagName("li"));
            try
            {
                links[index].Click();
            }
            catch
            {
                throw new InvalidOperationException($"No record with the index '{index}' exists.");
            }

            driver.WaitForPageToLoad();

            return true;
        }

        /// <summary>
        /// Close Record Set Navigator
        /// </summary>
        /// <param name="thinkTime"></param>
        /// <example>xrmApp.Entity.CloseRecordSetNavigator();</example>
        public bool CloseRecordSetNavigator(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var closeSpan = driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.RecordSetNavCollapseIcon]));
            if (closeSpan)
            {
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.RecordSetNavCollapseIconParent])).Click();
            }

            return true;
        }

        // Used by SetValue methods to determine the field context
        private IWebElement ValidateFormContext(IWebDriver driver, FormContextType formContextType, string field, IWebElement fieldContainer)
        {
            if (formContextType == FormContextType.QuickCreate)
            {
                // Initialize the quick create form context
                // If this is not done -- element input will go to the main form due to new flyout design
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.QuickCreateFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", field)));
            }
            else if (formContextType == FormContextType.Entity)
            {
                // Initialize the entity form context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", field)));
            }
            else if (formContextType == FormContextType.BusinessProcessFlow)
            {
                // Initialize the Business Process Flow context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.TextFieldContainer].Replace("[NAME]", field)));
            }
            else if (formContextType == FormContextType.Header)
            {
                // Initialize the Header context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.HeaderContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", field)));
            }
            else if (formContextType == FormContextType.Dialog)
            {
                // Initialize the Dialog context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", field)));
            }

            return fieldContainer;
        }

        /// <summary>
        /// Set Value
        /// </summary>
        /// <param name="field">The field</param>
        /// <param name="value">The value</param>
        /// <example>xrmApp.Entity.SetValue("firstname", "Test");</example>
        internal bool SetValue(string field, string value, FormContextType formContextType = FormContextType.Entity)
        {
            IWebElement fieldContainer = null;
            fieldContainer = ValidateFormContext(driver, formContextType, field, fieldContainer);

            IWebElement input;
            bool found = fieldContainer.TryFindElement(By.TagName("input"), out input);

            if (!found)
                found = fieldContainer.TryFindElement(By.TagName("textarea"), out input);

            if (!found)
                throw new NoSuchElementException($"Field with name {field} does not exist.");

            SetInputValue(driver, input, value);

            return true;
        }

        private void SetInputValue(IWebDriver driver, IWebElement input, string value, TimeSpan? thinktime = null)
        {
            // Repeat set value if expected value is not set
            // Do this to ensure that the static placeholder '---' is removed 
            driver.RepeatUntil(() =>
            {
                input.Clear();
                input.Click();
                input.SendKeys(Keys.Control + "a");
                input.SendKeys(Keys.Control + "a");
                input.SendKeys(Keys.Backspace);
                input.SendKeys(value);
                driver.WaitForTransaction();
            },
                d => input.GetAttribute("value").IsValueEqualsTo(value),
                TimeSpan.FromSeconds(9), 3,
                failureCallback: () => throw new InvalidOperationException($"Timeout after 10 seconds. Expected: {value}. Actual: {input.GetAttribute("value")}")
            );

            driver.WaitForTransaction();
        }

        /// <summary>
        /// Sets the value of a Lookup, Customer, Owner or ActivityParty Lookup which accepts only a single value.
        /// </summary>
        /// <param name="control">The lookup field name, value or index of the lookup.</param>
        /// <example>xrmApp.Entity.SetValue(new Lookup { Name = "prrimarycontactid", Value = "Rene Valdes (sample)" });</example>
        /// The default index position is 0, which will be the first result record in the lookup results window. Suppy a value > 0 to select a different record if multiple are present.
        internal bool SetValue(LookupItem control, FormContextType formContextType)
        {
            driver.WaitForTransaction();

            IWebElement fieldContainer = null;
            fieldContainer = ValidateFormContext(driver, formContextType, control.Name, fieldContainer);

            TryRemoveLookupValue(driver, fieldContainer, control);
            TrySetValue(driver, fieldContainer, control);

            return true;
        }

        private void TrySetValue(IWebDriver driver, IWebElement fieldContainer, LookupItem control)
        {
            IWebElement input;
            bool found = fieldContainer.TryFindElement(By.TagName("input"), out input);
            string value = control.Value?.Trim();
            if (found)
                SetInputValue(driver, input, value);

            TrySetValue(driver, control);
        }

        /// <summary>
        /// Sets the value of an ActivityParty Lookup.
        /// </summary>
        /// <param name="controls">The lookup field name, value or index of the lookup.</param>
        /// <example>xrmApp.Entity.SetValue(new Lookup[] { Name = "to", Value = "Rene Valdes (sample)" }, { Name = "to", Value = "Alpine Ski House (sample)" } );</example>
        /// The default index position is 0, which will be the first result record in the lookup results window. Suppy a value > 0 to select a different record if multiple are present.
        internal bool SetValue(LookupItem[] controls, FormContextType formContextType = FormContextType.Entity, bool clearFirst = true)
        {
            var control = controls.First();
            var controlName = control.Name;
            driver.WaitForTransaction();

            IWebElement fieldContainer = null;
            fieldContainer = ValidateFormContext(driver, formContextType, controlName, fieldContainer);

            if (clearFirst)
                TryRemoveLookupValue(driver, fieldContainer, control);

            TryToSetValue(driver, fieldContainer, controls);

            return true;
        }

        private void TryToSetValue(IWebDriver driver, ISearchContext fieldContainer, LookupItem[] controls)
        {
            IWebElement input;
            bool found = fieldContainer.TryFindElement(By.TagName("input"), out input);

            foreach (var control in controls)
            {
                var value = control.Value?.Trim();
                if (found)
                {
                    if (string.IsNullOrWhiteSpace(value))
                        input.Click();
                    else
                    {
                        input.SendKeys(value, true);
                        driver.WaitForTransaction();
                        ThinkTime(3.Seconds());
                        input.SendKeys(Keys.Tab);
                        input.SendKeys(Keys.Enter);
                    }
                }

                TrySetValue(fieldContainer, control);
            }

            input.SendKeys(Keys.Escape); // IE wants to keep the flyout open on multi-value fields, this makes sure it closes
        }

        private void TrySetValue(ISearchContext container, LookupItem control)
        {
            string value = control.Value;
            if (value == null)
                control.Value = string.Empty;
            // throw new InvalidOperationException($"No value has been provided for the LookupItem {control.Name}. Please provide a value or an empty string and try again.");

            if (control.Value == string.Empty)
                SetLookupByIndex(container, control);
            else
                SetLookUpByValue(container, control);
        }

        private void SetLookUpByValue(ISearchContext container, LookupItem control)
        {
            var controlName = control.Name;
            var xpathToText = AppElements.Xpath[AppReference.Entity.LookupFieldNoRecordsText].Replace("[NAME]", controlName);
            var xpathToResultList = AppElements.Xpath[AppReference.Entity.LookupFieldResultList].Replace("[NAME]", controlName);
            var bypathResultList = By.XPath(xpathToText + "|" + xpathToResultList);

            container.WaitUntilAvailable(bypathResultList, TimeSpan.FromSeconds(10));

            var byPathToFlyout = By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldLookupMenu].Replace("[NAME]", controlName));
            var flyoutDialog = container.WaitUntilClickable(byPathToFlyout);

            var items = GetListItems(flyoutDialog, control);

            if (items.Count == 0)
                throw new InvalidOperationException($"List does not contain a record with the name:  {control.Value}");

            int index = control.Index;
            if (index >= items.Count)
                throw new InvalidOperationException($"List does not contain {index + 1} records. Please provide an index value less than {items.Count} ");

            var selectedItem = items.ElementAt(index);
            selectedItem.Click(true);
        }

        private void SetLookupByIndex(ISearchContext container, LookupItem control)
        {
            var controlName = control.Name;
            var xpathToControl = By.XPath(AppElements.Xpath[AppReference.Entity.LookupResultsDropdown].Replace("[NAME]", controlName));
            var lookupResultsDialog = container.WaitUntilVisible(xpathToControl);

            var xpathFieldResultListItem = By.XPath(AppElements.Xpath[AppReference.Entity.LookupFieldResultListItem].Replace("[NAME]", controlName));
            container.WaitUntil(d => d.FindElements(xpathFieldResultListItem).Count > 0);

            var items = GetListItems(lookupResultsDialog, control);
            if (items.Count == 0)
                throw new InvalidOperationException($"No results exist in the Recently Viewed flyout menu. Please provide a text value for {controlName}");

            int index = control.Index;
            if (index >= items.Count)
                throw new InvalidOperationException($"Recently Viewed list does not contain {index} records. Please provide an index value less than {items.Count}");

            var selectedItem = items.ElementAt(index);
            selectedItem.Click(true);
        }

        /// <summary>
        /// Sets the value of a picklist or status field.
        /// </summary>
        /// <param name="control">The option you want to set.</param>
        /// <example>xrmApp.Entity.SetValue(new OptionSet { Name = "preferredcontactmethodcode", Value = "Email" });</example>
        public bool SetValue(OptionSet control, FormContextType formContextType)
        {
            var controlName = control.Name;
            IWebElement fieldContainer = null;
            fieldContainer = ValidateFormContext(driver, formContextType, controlName, fieldContainer);

            TrySetValue(fieldContainer, control);
            driver.WaitForTransaction();
            return true;
        }

        private static void TrySetValue(IWebElement fieldContainer, OptionSet control)
        {
            var value = control.Value;
            bool success = fieldContainer.TryFindElement(By.TagName("select"), out IWebElement select);
            if (success)
            {
                fieldContainer.WaitUntilAvailable(By.TagName("select"));
                var options = select.FindElements(By.TagName("option"));
                SelectOption(options, value);
                return;
            }

            var name = control.Name;
            var hasStatusCombo = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityOptionsetStatusCombo].Replace("[NAME]", name)));
            if (hasStatusCombo)
            {
                // This is for statuscode (type = status) that should act like an optionset doesn't doesn't follow the same pattern when rendered
                fieldContainer.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.EntityOptionsetStatusComboButton].Replace("[NAME]", name)));

                var listBox = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityOptionsetStatusComboList].Replace("[NAME]", name)));

                var options = listBox.FindElements(By.TagName("li"));
                SelectOption(options, value);
                return;
            }

            throw new InvalidOperationException($"OptionSet Field: '{name}' does not exist");
        }

        private static void SelectOption(ReadOnlyCollection<IWebElement> options, string value)
        {
            var selectedOption = options.FirstOrDefault(op => op.Text == value || op.GetAttribute("value") == value);
            selectedOption.Click(true);
        }

        /// <summary>
        /// Sets the value of a Boolean Item.
        /// </summary>
        /// <param name="option">The boolean field name.</param>
        /// <example>xrmApp.Entity.SetValue(new BooleanItem { Name = "donotemail", Value = true });</example>
        public bool SetValue(BooleanItem option, FormContextType formContextType)
        {
            // ensure that the option.Name value is lowercase -- will cause XPath lookup issues
            option.Name = option.Name.ToLowerInvariant();

            IWebElement fieldContainer = null;
            fieldContainer = ValidateFormContext(driver, formContextType, option.Name, fieldContainer);

            var hasRadio = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldRadioContainer].Replace("[NAME]", option.Name)));
            var hasCheckbox = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldCheckbox].Replace("[NAME]", option.Name)));
            var hasList = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldList].Replace("[NAME]", option.Name)));
            var hasToggle = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldToggle].Replace("[NAME]", option.Name)));
            var hasFlipSwitch = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldFlipSwitchLink].Replace("[NAME]", option.Name)));

            // Need to validate whether control is FlipSwitch or Button
            IWebElement flipSwitchContainer = null;
            var flipSwitch = hasFlipSwitch ? fieldContainer.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldFlipSwitchContainer].Replace("[NAME]", option.Name)), out flipSwitchContainer) : false;
            var hasButton = flipSwitchContainer != null ? flipSwitchContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldButtonTrue])) : false;
            hasFlipSwitch = hasButton ? false : hasFlipSwitch; //flipSwitch and button have the same container reference, so if it has a button it is not a flipSwitch
            hasFlipSwitch = hasToggle ? false : hasFlipSwitch; //flipSwitch and Toggle have the same container reference, so if it has a Toggle it is not a flipSwitch

            if (hasRadio)
            {
                var trueRadio = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldRadioTrue].Replace("[NAME]", option.Name)));
                var falseRadio = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldRadioFalse].Replace("[NAME]", option.Name)));

                if (option.Value && bool.Parse(falseRadio.GetAttribute("aria-checked")) || !option.Value && bool.Parse(trueRadio.GetAttribute("aria-checked")))
                {
                    driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldRadioContainer].Replace("[NAME]", option.Name)));
                }
            }
            else if (hasCheckbox)
            {
                var checkbox = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldCheckbox].Replace("[NAME]", option.Name)));

                if (option.Value && !checkbox.Selected || !option.Value && checkbox.Selected)
                {
                    driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldCheckboxContainer].Replace("[NAME]", option.Name)));
                }
            }
            else if (hasList)
            {
                var list = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldList].Replace("[NAME]", option.Name)));
                var options = list.FindElements(By.TagName("option"));
                var selectedOption = options.FirstOrDefault(a => a.HasAttribute("data-selected") && bool.Parse(a.GetAttribute("data-selected")));
                var unselectedOption = options.FirstOrDefault(a => !a.HasAttribute("data-selected"));

                var trueOptionSelected = false;
                if (selectedOption != null)
                {
                    trueOptionSelected = selectedOption.GetAttribute("value") == "1";
                }

                if (option.Value && !trueOptionSelected || !option.Value && trueOptionSelected)
                {
                    if (unselectedOption != null)
                    {
                        driver.ClickWhenAvailable(By.Id(unselectedOption.GetAttribute("id")));
                    }
                }
            }
            else if (hasToggle)
            {
                var toggle = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldToggle].Replace("[NAME]", option.Name)));
                var link = toggle.FindElement(By.TagName("button"));
                var value = bool.Parse(link.GetAttribute("aria-checked"));

                if (value != option.Value)
                {
                    link.Click();
                }
            }
            else if (hasFlipSwitch)
            {
                // flipSwitchContainer should exist based on earlier TryFindElement logic
                var link = flipSwitchContainer.FindElement(By.TagName("a"));
                var value = bool.Parse(link.GetAttribute("aria-checked"));

                if (value != option.Value)
                {
                    link.Click();
                }
            }
            else if (hasButton)
            {
                var container = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldButtonContainer].Replace("[NAME]", option.Name)));
                var trueButton = container.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldButtonTrue]));
                var falseButton = container.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldButtonFalse]));

                if (option.Value)
                {
                    trueButton.Click();
                }
                else
                {
                    falseButton.Click();
                }
            }
            else
                throw new InvalidOperationException($"Field: {option.Name} Does not exist");


            return true;

        }

        /// <summary>
        /// Sets the value of a Date Field.
        /// </summary>
        /// <param name="field">Date field name.</param>
        /// <param name="value">DateTime value.</param>
        /// <param name="formatDate">Datetime format matching Short Date formatting personal options.</param>
        /// <param name="formatTime">Datetime format matching Short Time formatting personal options.</param>
        /// <example>xrmApp.Entity.SetValue("birthdate", DateTime.Parse("11/1/1980"));</example>
        /// <example>xrmApp.Entity.SetValue("new_actualclosedatetime", DateTime.Now, "MM/dd/yyyy", "hh:mm tt");</example>
        /// <example>xrmApp.Entity.SetValue("estimatedclosedate", DateTime.Now);</example>
        public bool SetValue(string field, DateTime value, FormContextType formContext, string formatDate = null, string formatTime = null)
        {
            var control = new DateTimeControl(field)
            {
                Value = value,
                DateFormat = formatDate,
                TimeFormat = formatTime
            };
            return SetValue(control, formContext);
        }

        public bool SetValue(DateTimeControl control, FormContextType formContext)
        {
            return TrySetValue(driver, container: driver, control: control, formContext);
        }


        private bool TrySetValue(IWebDriver driver, ISearchContext container, DateTimeControl control, FormContextType formContext)
        {
            TrySetDateValue(driver, container, control, formContext);
            TrySetTime(driver, container, control, formContext);

            if (formContext == FormContextType.Header)
            {
                TryCloseHeaderFlyout(driver);
            }

            return true;
        }

        private void TrySetDateValue(IWebDriver driver, ISearchContext container, DateTimeControl control, FormContextType formContextType)
        {
            string controlName = control.Name;
            IWebElement fieldContainer = null;
            var xpathToInput = By.XPath(AppElements.Xpath[AppReference.Entity.FieldControlDateTimeInputUCI].Replace("[FIELD]", controlName));

            if (formContextType == FormContextType.QuickCreate)
            {
                // Initialize the quick create form context
                // If this is not done -- element input will go to the main form due to new flyout design
                var formContext = container.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.QuickCreateFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(xpathToInput, $"DateTime Field: '{controlName}' does not exist");

                var strExpanded = fieldContainer.GetAttribute("aria-expanded");

                if (strExpanded == null)
                {
                    fieldContainer = formContext.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", controlName)));
                }
            }
            else if (formContextType == FormContextType.Entity)
            {
                // Initialize the entity form context
                var formContext = container.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormContext]));
                fieldContainer = formContext.WaitUntilAvailable(xpathToInput, $"DateTime Field: '{controlName}' does not exist");

                var strExpanded = fieldContainer.GetAttribute("aria-expanded");

                if (strExpanded == null)
                {
                    fieldContainer = formContext.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", controlName)));
                }
            }
            else if (formContextType == FormContextType.BusinessProcessFlow)
            {
                // Initialize the Business Process Flow context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(xpathToInput, $"DateTime Field: '{controlName}' does not exist");

                var strExpanded = fieldContainer.GetAttribute("aria-expanded");

                if (strExpanded == null)
                {
                    fieldContainer = formContext.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", controlName)));
                }
            }
            else if (formContextType == FormContextType.Header)
            {
                // Initialize the Header context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.HeaderContext]));
                fieldContainer = formContext.WaitUntilAvailable(xpathToInput, $"DateTime Field: '{controlName}' does not exist");

                var strExpanded = fieldContainer.GetAttribute("aria-expanded");

                if (strExpanded == null)
                {
                    fieldContainer = formContext.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", controlName)));
                }
            }
            else if (formContextType == FormContextType.Dialog)
            {
                // Initialize the Dialog context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]));
                fieldContainer = formContext.WaitUntilAvailable(xpathToInput, $"DateTime Field: '{controlName}' does not exist");

                var strExpanded = fieldContainer.GetAttribute("aria-expanded");

                if (strExpanded == null)
                {
                    fieldContainer = formContext.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", controlName)));
                }

            }

            TrySetDateValue(driver, fieldContainer, control.DateAsString, formContextType);
        }

        private void TrySetDateValue(IWebDriver driver, IWebElement dateField, string date, FormContextType formContextType)
        {
            var strExpanded = dateField.GetAttribute("aria-expanded");

            if (strExpanded != null)
            {
                bool success = bool.TryParse(strExpanded, out var isCalendarExpanded);
                if (success && isCalendarExpanded)
                    dateField.Click(); // close calendar

                driver.RepeatUntil(() =>
                {
                    ClearFieldValue(dateField);
                    if (date != null)
                        dateField.SendKeys(date);
                },
                    d => dateField.GetAttribute("value").IsValueEqualsTo(date),
                    TimeSpan.FromSeconds(9), 3,
                    failureCallback: () => throw new InvalidOperationException($"Timeout after 10 seconds. Expected: {date}. Actual: {dateField.GetAttribute("value")}")
                );
            }
            else
            {
                driver.RepeatUntil(() =>
                {
                    dateField.Click(true);
                    if (date != null)
                    {
                        dateField = dateField.FindElement(By.TagName("input"));

                        // Only send Keys.Escape to avoid element not interactable exceptions with calendar flyout on forms.
                        // This can cause the Header or BPF flyouts to close unexpectedly
                        if (formContextType == FormContextType.Entity || formContextType == FormContextType.QuickCreate)
                        {
                            dateField.SendKeys(Keys.Escape);
                        }

                        ClearFieldValue(dateField);
                        dateField.SendKeys(date);
                    }
                },
                    d => dateField.GetAttribute("value").IsValueEqualsTo(date),
                    TimeSpan.FromSeconds(9), 3,
                    failureCallback: () => throw new InvalidOperationException($"Timeout after 10 seconds. Expected: {date}. Actual: {dateField.GetAttribute("value")}")
                );
            }
        }

        private void ClearFieldValue(IWebElement field)
        {
            if (field.GetAttribute("value").Length > 0)
            {
                field.SendKeys(Keys.Control + "a");
                field.SendKeys(Keys.Backspace);
            }

            ThinkTime(500);
        }

        private static void TrySetTime(IWebDriver driver, ISearchContext container, DateTimeControl control, FormContextType formContextType)
        {
            By timeFieldXPath = By.XPath(AppElements.Xpath[AppReference.Entity.FieldControlDateTimeTimeInputUCI].Replace("[FIELD]", control.Name));

            IWebElement formContext = null;

            if (formContextType == FormContextType.QuickCreate)
            {
                //IWebDriver formContext;
                // Initialize the quick create form context
                // If this is not done -- element input will go to the main form due to new flyout design
                formContext = container.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.QuickCreateFormContext]), new TimeSpan(0, 0, 1));
            }
            else if (formContextType == FormContextType.Entity)
            {
                // Initialize the entity form context
                formContext = container.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormContext]), new TimeSpan(0, 0, 1));
            }
            else if (formContextType == FormContextType.BusinessProcessFlow)
            {
                // Initialize the Business Process Flow context
                formContext = container.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFormContext]), new TimeSpan(0, 0, 1));
            }
            else if (formContextType == FormContextType.Header)
            {
                // Initialize the Header context
                formContext = container as IWebElement;
            }
            else if (formContextType == FormContextType.Dialog)
            {
                // Initialize the Header context
                formContext = container.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]), new TimeSpan(0, 0, 1));
            }

            var success = formContext.TryFindElement(timeFieldXPath, out var timeField);
            if (success)
                TrySetTime(driver, timeField, control.TimeAsString);

        }

        private static void TrySetTime(IWebDriver driver, IWebElement timeField, string time)
        {
            // click & wait until the time get updated after change/clear the date
            timeField.Click();
            driver.WaitForTransaction();

            driver.RepeatUntil(() =>
            {
                timeField.Clear();
                timeField.Click();
                timeField.SendKeys(time);
                timeField.SendKeys(Keys.Tab);
                driver.WaitForTransaction();
            },
                d => timeField.GetAttribute("value").IsValueEqualsTo(time),
                TimeSpan.FromSeconds(9), 3,
                failureCallback: () => throw new InvalidOperationException($"Timeout after 10 seconds. Expected: {time}. Actual: {timeField.GetAttribute("value")}")
            );
        }


        /// <summary>
        /// Sets/Removes the value from the multselect type control
        /// </summary>
        /// <param name="option">Object of type MultiValueOptionSet containing name of the Field and the values to be set/removed</param>
        /// <param name="removeExistingValues">False - Values will be set. True - Values will be removed</param>
        /// <returns>True on success</returns>
        internal bool SetValue(MultiValueOptionSet option, FormContextType formContextType = FormContextType.Entity, bool removeExistingValues = false)
        {
            if (removeExistingValues)
            {
                RemoveMultiOptions(option, formContextType);
            }


            AddMultiOptions(option, formContextType);

            return true;
        }

        /// <summary>
        /// Removes the value from the multselect type control
        /// </summary>
        /// <param name="option">Object of type MultiValueOptionSet containing name of the Field and the values to be removed</param>
        /// <returns></returns>
        private bool RemoveMultiOptions(MultiValueOptionSet option, FormContextType formContextType)
        {
            IWebElement fieldContainer = null;

            if (formContextType == FormContextType.QuickCreate)
            {
                // Initialize the quick create form context
                // If this is not done -- element input will go to the main form due to new flyout design
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.QuickCreateFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.Entity)
            {
                // Initialize the entity form context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.BusinessProcessFlow)
            {
                // Initialize the Business Process Flow context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.Header)
            {
                // Initialize the Header context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.HeaderContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.Dialog)
            {
                // Initialize the Header context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }

            fieldContainer.Hover(driver, true);

            var selectedRecordXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.SelectedRecord]);
            var selectedRecords = fieldContainer.FindElements(selectedRecordXPath);

            var initialCountOfSelectedOptions = selectedRecords.Count;
            var deleteButtonXpath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.SelectedOptionDeleteButton]);
            for (int i = 0; i < initialCountOfSelectedOptions; i++)
            {
                // With every click of the button, the underlying DOM changes and the
                // entire collection becomes stale, hence we only click the first occurance of
                // the button and loop back to again find the elements and anyother occurance
                selectedRecords[0].FindElement(deleteButtonXpath).Click(true);
                driver.WaitForTransaction();
                selectedRecords = fieldContainer.FindElements(selectedRecordXPath);
            }

            return true;
        }

        /// <summary>
        /// Sets the value from the multselect type control
        /// </summary>
        /// <param name="option">Object of type MultiValueOptionSet containing name of the Field and the values to be set</param>
        /// <returns></returns>
        private bool AddMultiOptions(MultiValueOptionSet option, FormContextType formContextType)
        {
            IWebElement fieldContainer = null;

            if (formContextType == FormContextType.QuickCreate)
            {
                // Initialize the quick create form context
                // If this is not done -- element input will go to the main form due to new flyout design
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.QuickCreate.QuickCreateFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.Entity)
            {
                // Initialize the entity form context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.BusinessProcessFlow)
            {
                // Initialize the Business Process Flow context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFormContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.Header)
            {
                // Initialize the Header context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.HeaderContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }
            else if (formContextType == FormContextType.Dialog)
            {
                // Initialize the Header context
                var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]));
                fieldContainer = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name)));
            }

            var inputXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.InputSearch]);
            fieldContainer.FindElement(inputXPath).SendKeys(string.Empty);

            var flyoutCaretXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.FlyoutCaret]);
            fieldContainer.FindElement(flyoutCaretXPath).Click();

            foreach (var optionValue in option.Values)
            {
                var flyoutOptionXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.FlyoutOption].Replace("[NAME]", optionValue));
                if (fieldContainer.TryFindElement(flyoutOptionXPath, out var flyoutOption))
                {
                    var ariaSelected = flyoutOption.GetAttribute<string>("aria-selected");
                    var selected = !string.IsNullOrEmpty(ariaSelected) && bool.Parse(ariaSelected);

                    if (!selected)
                    {
                        flyoutOption.Click();
                    }
                }
            }
            return true;
        }

        internal Field GetField(string field)
        {
            var fieldElement = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", field)));
            Field returnField = new Field(fieldElement);
            returnField.Name = field;

            IWebElement fieldLabel = null;
            try
            {
                fieldLabel = fieldElement.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldLabel].Replace("[NAME]", field)));
            }
            catch (NoSuchElementException)
            {
                // Swallow
            }

            if (fieldLabel != null)
            {
                returnField.Label = fieldLabel.Text;
            }

            return returnField;
        }

        internal string GetValue(string field)
        {

            string text = string.Empty;
            var fieldContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", field)));

            if (fieldContainer.FindElements(By.TagName("input")).Count > 0)
            {
                var input = fieldContainer.FindElement(By.TagName("input"));
                if (input != null)
                {
                    //IWebElement fieldValue = input.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldValue].Replace("[NAME]", field)));
                    text = input.GetAttribute("value").ToString();

                    // Needed if getting a date field which also displays time as there isn't a date specifc GetValue method
                    var timefields = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.FieldControlDateTimeTimeInputUCI].Replace("[FIELD]", field)));
                    if (timefields.Any())
                    {
                        text += $" {timefields.First().GetAttribute("value")}";
                    }
                }
            }
            else if (fieldContainer.FindElements(By.TagName("textarea")).Count > 0)
            {
                text = fieldContainer.FindElement(By.TagName("textarea")).GetAttribute("value");
            }
            else
            {
                throw new Exception($"Field with name {field} does not exist.");
            }

            return text;
        }

        /// <summary>
        /// Gets the value of a Lookup.
        /// </summary>
        /// <param name="control">The lookup field name of the lookup.</param>
        /// <example>xrmApp.Entity.GetValue(new Lookup { Name = "primarycontactid" });</example>
        public string GetValue(LookupItem control)
        {
            var controlName = control.Name;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.TextFieldLookupFieldContainer].Replace("[NAME]", controlName);
            IWebElement fieldContainer = driver.WaitUntilAvailable(By.XPath(xpathToContainer));
            string lookupValue = TryGetValue(fieldContainer, control);

            return lookupValue;
        }
        private string TryGetValue(IWebElement fieldContainer, LookupItem control)
        {
            string[] lookupValues = TryGetValue(fieldContainer, new[] { control });
            string result = string.Join("; ", lookupValues);
            return result;
        }

        /// <summary>
        /// Gets the value of an ActivityParty Lookup.
        /// </summary>
        /// <param name="controls">The lookup field name of the lookup.</param>
        /// <example>xrmApp.Entity.GetValue(new LookupItem[] { new LookupItem { Name = "to" } });</example>
        public string[] GetValue(LookupItem[] controls)
        {
            var controlName = controls.First().Name;
            var xpathToContainer = By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldLookupFieldContainer].Replace("[NAME]", controlName));
            var fieldContainer = driver.WaitUntilAvailable(xpathToContainer);
            string[] result = TryGetValue(fieldContainer, controls);

            return result;

        }

        private string[] TryGetValue(IWebElement fieldContainer, LookupItem[] controls)
        {
            var controlName = controls.First().Name;
            var xpathToExistingValues = By.XPath(AppElements.Xpath[AppReference.Entity.LookupFieldExistingValue].Replace("[NAME]", controlName));
            var existingValues = fieldContainer.FindElements(xpathToExistingValues);

            var xpathToExpandButton = By.XPath(AppElements.Xpath[AppReference.Entity.LookupFieldExpandCollapseButton].Replace("[NAME]", controlName));
            bool expandButtonFound = fieldContainer.TryFindElement(xpathToExpandButton, out var expandButton);
            if (expandButtonFound)
            {
                expandButton.Click(true);

                int count = existingValues.Count;
                fieldContainer.WaitUntil(fc => fc.FindElements(xpathToExistingValues).Count > count);

                existingValues = fieldContainer.FindElements(xpathToExistingValues);
            }

            Exception ex = null;
            try
            {
                if (existingValues.Count > 0)
                {
                    string[] lookupValues = existingValues.Select(v => v.GetAttribute("innerText").TrimSpecialCharacters()).ToArray(); //IE can return line breaks
                    return lookupValues;
                }

                if (fieldContainer.FindElements(By.TagName("input")).Any())
                    return new string[0];
            }
            catch (Exception e)
            {
                ex = e;
            }

            throw new InvalidOperationException($"Field: {controlName} Does not exist", ex);
        }

        /// <summary>
        /// Gets the value of a picklist or status field.
        /// </summary>
        /// <param name="control">The option you want to set.</param>
        /// <example>xrmApp.Entity.GetValue(new OptionSet { Name = "preferredcontactmethodcode"}); </example>
        internal string GetValue(OptionSet control)
        {
            var controlName = control.Name;
            var xpathToFieldContainer = AppElements.Xpath[AppReference.Entity.OptionSetFieldContainer].Replace("[NAME]", controlName);
            var fieldContainer = driver.WaitUntilAvailable(By.XPath(xpathToFieldContainer));
            string result = TryGetValue(fieldContainer, control);

            return result;
        }

        private static string TryGetValue(IWebElement fieldContainer, OptionSet control)
        {
            bool success = fieldContainer.TryFindElement(By.TagName("select"), out IWebElement select);
            if (success)
            {
                var options = select.FindElements(By.TagName("option"));
                string result = GetSelectedOption(options);
                return result;
            }

            var name = control.Name;
            var hasStatusCombo = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityOptionsetStatusCombo].Replace("[NAME]", name)));
            if (hasStatusCombo)
            {
                // This is for statuscode (type = status) that should act like an optionset doesn't doesn't follow the same pattern when rendered
                var valueSpan = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityOptionsetStatusTextValue].Replace("[NAME]", name)));
                return valueSpan.Text;
            }

            throw new InvalidOperationException($"OptionSet Field: '{name}' does not exist");
        }

        private static string GetSelectedOption(ReadOnlyCollection<IWebElement> options)
        {
            var selectedOption = options.FirstOrDefault(op => op.Selected);
            return selectedOption?.Text ?? string.Empty;
        }

        /// <summary>
        /// Sets the value of a Boolean Item.
        /// </summary>
        /// <param name="option">The boolean field name.</param>
        /// <example>xrmApp.Entity.GetValue(new BooleanItem { Name = "creditonhold" });</example>
        internal bool GetValue(BooleanItem option)
        {
            var check = false;

            var fieldContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", option.Name)));

            var hasRadio = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldRadioContainer].Replace("[NAME]", option.Name)));
            var hasCheckbox = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldCheckbox].Replace("[NAME]", option.Name)));
            var hasList = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldList].Replace("[NAME]", option.Name)));
            var hasToggle = fieldContainer.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldToggle].Replace("[NAME]", option.Name)));

            if (hasRadio)
            {
                var trueRadio = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldRadioTrue].Replace("[NAME]", option.Name)));

                check = bool.Parse(trueRadio.GetAttribute("aria-checked"));
            }
            else if (hasCheckbox)
            {
                var checkbox = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldCheckbox].Replace("[NAME]", option.Name)));

                check = bool.Parse(checkbox.GetAttribute("aria-checked"));
            }
            else if (hasList)
            {
                var list = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldList].Replace("[NAME]", option.Name)));
                var options = list.FindElements(By.TagName("option"));
                var selectedOption = options.FirstOrDefault(a => a.HasAttribute("data-selected") && bool.Parse(a.GetAttribute("data-selected")));

                if (selectedOption != null)
                {
                    check = int.Parse(selectedOption.GetAttribute("value")) == 1;
                }
            }
            else if (hasToggle)
            {
                var toggle = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityBooleanFieldToggle].Replace("[NAME]", option.Name)));
                var link = toggle.FindElement(By.TagName("button"));

                check = bool.Parse(link.GetAttribute("aria-checked"));
            }
            else
                throw new InvalidOperationException($"Field: {option.Name} Does not exist");

            return check;
        }

        /// <summary>
        /// Gets the value from the multselect type control
        /// </summary>
        /// <param name="option">Object of type MultiValueOptionSet containing name of the Field</param>
        /// <returns>MultiValueOptionSet object where the values field contains all the contact names</returns>
        internal MultiValueOptionSet GetValue(MultiValueOptionSet option)
        {
            var containerXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.DivContainer].Replace("[NAME]", option.Name));
            var container = driver.WaitUntilAvailable(containerXPath, $"Multi-select option set {option.Name} not found.");

            container.Hover(driver, true);
            var expandButtonXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.ExpandCollapseButton]);
            if (container.TryFindElement(expandButtonXPath, out var expandButton) && expandButton.IsClickable())
            {
                expandButton.Click();
            }

            var selectedOptionsXPath = By.XPath(AppElements.Xpath[AppReference.MultiSelect.SelectedRecordLabel]);
            var selectedOptions = container.FindElements(selectedOptionsXPath);

            return new MultiValueOptionSet
            {
                Name = option.Name,
                Values = selectedOptions.Select(o => o.Text).ToArray()
            };
        }


        /// <summary>
        /// Gets the value of a Lookup.
        /// </summary>
        /// <param name="control">The lookup field name of the lookup.</param>
        /// <example>xrmApp.Entity.GetValue(new DateTimeControl { Name = "scheduledstart" });</example>
        public DateTime? GetValue(DateTimeControl control)
        { return TryGetValue(driver, container: driver, control: control); }

        private static DateTime? TryGetValue(IWebDriver driver, ISearchContext container, DateTimeControl control)
        {
            string field = control.Name;
            driver.WaitForTransaction();

            var xpathToDateField = By.XPath(AppElements.Xpath[AppReference.Entity.FieldControlDateTimeInputUCI].Replace("[FIELD]", field));

            var dateField = container.WaitUntilAvailable(xpathToDateField, $"Field: {field} Does not exist");
            string strDate = dateField.GetAttribute("value");
            if (strDate.IsEmptyValue())
                return null;

            var date = DateTime.Parse(strDate);

            // Try get Time
            var timeFieldXPath = By.XPath(AppElements.Xpath[AppReference.Entity.FieldControlDateTimeTimeInputUCI].Replace("[FIELD]", field));
            bool success = container.TryFindElement(timeFieldXPath, out var timeField);
            if (!success || timeField == null)
                return date;

            string strTime = timeField.GetAttribute("value");
            if (strTime.IsEmptyValue())
                return date;

            var time = DateTime.Parse(strTime);

            var result = date.AddHours(time.Hour).AddMinutes(time.Minute).AddSeconds(time.Second);

            return result;
        }

        /// <summary>
        /// Returns the ObjectId of the entity
        /// </summary>
        /// <returns>Guid of the Entity</returns>
        internal Guid GetObjectId(int thinkTime = Constants.DefaultThinkTime)
        {
            var objectId = driver.ExecuteScript("return Xrm.Page.data.entity.getId();");

            Guid oId;
            if (!Guid.TryParse(objectId.ToString(), out oId))
                throw new NotFoundException("Unable to retrieve object Id for this entity");

            return oId;
        }

        /// <summary>
        /// Returns the Entity Name of the entity
        /// </summary>
        /// <returns>Entity Name of the Entity</returns>
        internal string GetEntityName(int thinkTime = Constants.DefaultThinkTime)
        {
            var entityName = driver.ExecuteScript("return Xrm.Page.data.entity.getEntityName();").ToString();

            if (string.IsNullOrEmpty(entityName))
            {
                throw new NotFoundException("Unable to retrieve Entity Name for this entity");
            }

            return entityName;
        }

        /// <summary>
        /// Returns the Form Name of the entity
        /// </summary>
        /// <returns>Form Name of the Entity</returns>
        internal string GetFormName(int thinkTime = Constants.DefaultThinkTime)
        {
            // Wait for form selector visible
            driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Entity.FormSelector]));

            string formName = driver.ExecuteScript("return Xrm.Page.ui.formContext.ui.formSelector.getCurrentItem().getLabel();").ToString();

            if (string.IsNullOrEmpty(formName))
            {
                throw new NotFoundException("Unable to retrieve Form Name for this entity");
            }

            return formName;
        }

        /// <summary>
        /// Returns the Header Title of the entity
        /// </summary>
        /// <returns>Header Title of the Entity</returns>
        internal string GetHeaderTitle(int thinkTime = Constants.DefaultThinkTime)
        {
            // Wait for form selector visible
            var headerTitle = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Entity.HeaderTitle]), new TimeSpan(0, 0, 5));

            var headerTitleName = headerTitle?.Text;

            if (string.IsNullOrEmpty(headerTitleName))
            {
                throw new NotFoundException("Unable to retrieve Header Title for this entity");
            }

            return headerTitleName;

        }


        internal List<GridItem> GetSubGridItems(string subgridName)
        {
            // Initialize return object
            List<GridItem> subGridRows = new List<GridItem>();

            // Initialize required local variables
            IWebElement subGridRecordList = null;
            List<string> columns = new List<string>();
            List<string> cellValues = new List<string>();
            GridItem item = new GridItem();

            // Find the SubGrid
            var subGrid = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridContents].Replace("[NAME]", subgridName)));

            if (subGrid == null)
                throw new NotFoundException($"Unable to locate subgrid contents for {subgridName} subgrid.");

            // Check if ReadOnlyGrid was found
            if (subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridList].Replace("[NAME]", subgridName)), out subGridRecordList))
            {
                // Locate record list
                var foundRecords = subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridList].Replace("[NAME]", subgridName)), out subGridRecordList);

                if (foundRecords)
                {
                    var subGridRecordRows = subGridRecordList.FindElements(By.TagName("li"));

                    foreach (IWebElement recordRow in subGridRecordRows)
                    {
                        var recordLabels = recordRow.FindElements(By.TagName("label"));

                        foreach (IWebElement label in recordLabels)
                        {
                            if (label.GetAttribute("id") != null)
                            {
                                var headerLabelId = label.GetAttribute("id").ToString();

                                var frontLength = (43 + (subgridName.Length) + 15);
                                var rearLength = 37;
                                // Trim calculated frontLength
                                var headerLabel = headerLabelId.Remove(0, frontLength);

                                // Trim calculated rearLength
                                headerLabel = headerLabel.Remove((headerLabel.Length - rearLength), rearLength);
                                columns.Add(headerLabel);

                                var rowText = label.Text;
                                cellValues.Add(rowText);
                            }
                        }


                        for (int i = 0; i < columns.Count; i++)
                        {
                            item[columns[i]] = cellValues[i];
                        }

                        subGridRows.Add(item);

                        // Flush Item and Cell Values To Get New Rows
                        cellValues = new List<string>();
                        item = new GridItem();
                    }

                }
                else
                    throw new NotFoundException($"Unable to locate record list for subgrid {subgridName}");

            }
            // Attempt to locate the editable grid list
            else if (subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EditableSubGridList].Replace("[NAME]", subgridName)), out subGridRecordList))
            {
                //Find the columns
                var headerCells = subGrid.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridHeadersEditable]));

                foreach (IWebElement headerCell in headerCells)
                {
                    var headerTitle = headerCell.GetAttribute("title");
                    columns.Add(headerTitle);
                }

                //Find the rows
                var rows = subGrid.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridDataRowsEditable]));

                //Process each row
                foreach (IWebElement row in rows)
                {
                    var cells = row.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCells]));

                    if (cells.Count > 0)
                    {
                        foreach (IWebElement thisCell in cells)
                            cellValues.Add(thisCell.Text);

                        for (int i = 0; i < columns.Count; i++)
                        {
                            //The first cell is always a checkbox for the record.  Ignore the checkbox.
                            if (i == 0)
                            {
                                // Do Nothing
                            }
                            else
                            {
                                item[columns[i]] = cellValues[i];
                            }
                        }

                        subGridRows.Add(item);

                        // Flush Item and Cell Values To Get New Rows
                        cellValues = new List<string>();
                        item = new GridItem();
                    }
                }

                return subGridRows;

            }
            // Special 'Related' high density grid control for entity forms
            else if (subGrid.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridHighDensityList].Replace("[NAME]", subgridName)), out subGridRecordList))
            {
                //Find the columns
                var headerCells = subGrid.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridHeadersHighDensity]));

                foreach (IWebElement headerCell in headerCells)
                {
                    var headerTitle = headerCell.GetAttribute("data-id");
                    columns.Add(headerTitle);
                }

                //Find the rows
                var rows = subGrid.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridRowsHighDensity]));

                //Process each row
                foreach (IWebElement row in rows)
                {
                    //Get the entityId and entity Type
                    if (row.GetAttribute("data-lp-id") != null)
                    {
                        var rowAttributes = row.GetAttribute("data-lp-id").Split('|');
                        item.EntityName = rowAttributes[4];
                        //The row record IDs are not in the DOM. Must be retrieved via JavaScript
                        var getId = $"return Xrm.Page.getControl(\"{subgridName}\").getGrid().getRows().get({rows.IndexOf(row)}).getData().entity.getId()";
                        item.Id = new Guid((string)driver.ExecuteScript(getId));
                    }

                    var cells = row.FindElements(By.XPath(AppElements.Xpath[AppReference.Entity.SubGridCells]));

                    if (cells.Count > 0)
                    {
                        foreach (IWebElement thisCell in cells)
                            cellValues.Add(thisCell.Text);

                        for (int i = 0; i < columns.Count; i++)
                        {
                            //The first cell is always a checkbox for the record.  Ignore the checkbox.
                            if (i == 0)
                            {
                                // Do Nothing
                            }
                            else
                            {
                                item[columns[i]] = cellValues[i];
                            }

                        }

                        subGridRows.Add(item);

                        // Flush Item and Cell Values To Get New Rows
                        cellValues = new List<string>();
                        item = new GridItem();
                    }
                }

                return subGridRows;
            }

            // Return rows object
            return subGridRows;
        }



        internal int GetSubGridItemsCount(string subgridName)
        {
            List<GridItem> rows = GetSubGridItems(subgridName);
            return rows.Count;
        }

        /// <summary>
        /// Click the magnifying glass icon for the lookup control supplied
        /// </summary>
        /// <param name="control">The LookupItem field on the form</param>
        /// <returns></returns>
        internal bool SelectLookup(LookupItem control)
        {
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.FieldLookupButton].Replace("[NAME]", control.Name))))
            {
                var lookupButton = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FieldLookupButton].Replace("[NAME]", control.Name)));

                lookupButton.Hover(driver);

                driver.WaitForTransaction();

                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.SearchButtonIcon])).Click(true);
            }
            else
                throw new NotFoundException($"Lookup field {control.Name} not found");

            driver.WaitForTransaction();

            return true;
        }

        internal string GetHeaderValue(LookupItem control)
        {
            var controlName = control.Name;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.LookupFieldContainer].Replace("[NAME]", controlName);
            string lookupValue = ExecuteInHeaderContainer(driver, xpathToContainer, container => TryGetValue(container, control));

            return lookupValue;
        }

        internal string[] GetHeaderValue(LookupItem[] controls)
        {
            var controlName = controls.First().Name;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.LookupFieldContainer].Replace("[NAME]", controlName);

            string[] lookupValues = ExecuteInHeaderContainer(driver, xpathToContainer, container => TryGetValue(container, controls));

            return lookupValues;
        }

        internal string GetHeaderValue(string control)
        {
            TryExpandHeaderFlyout(driver);

            return GetValue(control);
        }

        internal MultiValueOptionSet GetHeaderValue(MultiValueOptionSet control)
        {
            TryExpandHeaderFlyout(driver);

            return GetValue(control);

        }

        internal string GetHeaderValue(OptionSet control)
        {
            var controlName = control.Name;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.OptionSetFieldContainer].Replace("[NAME]", controlName);
            return ExecuteInHeaderContainer(driver, xpathToContainer, container => TryGetValue(container, control));
        }

        internal bool GetHeaderValue(BooleanItem control)
        {
            TryExpandHeaderFlyout(driver);

            return GetValue(control);
        }

        internal DateTime? GetHeaderValue(DateTimeControl control)
        {
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.DateTimeFieldContainer].Replace("[NAME]", control.Name);
            return ExecuteInHeaderContainer(driver, xpathToContainer,
                    container => TryGetValue(driver, container, control));
        }

        internal string GetStatusFromFooter()
        {
            IWebElement footer;
            var footerExists = driver.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityFooter]), out footer);

            IWebElement status;
            footer.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FooterStatusValue]), out status);

            if (footerExists)
            {
                if (String.IsNullOrEmpty(status.Text))
                    return "unknown";

                return status.Text;
            }
            else
                throw new NoSuchElementException("Unable to find the footer on the entity form");
        }

        internal string GetMessageFromFooter()
        {
            IWebElement footer;
            var footerExists = driver.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.EntityFooter]), out footer);

            if (footerExists)
            {
                IWebElement message;
                footer.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FooterMessageValue]), out message);

                if (String.IsNullOrEmpty(message.Text))
                    return string.Empty;

                return message.Text;
            }
            else
                throw new NoSuchElementException("Unable to find the footer on the entity form");

        }

        internal bool SetHeaderValue(string field, string value)
        {
            TryExpandHeaderFlyout(driver);

            SetValue(field, value, FormContextType.Header);

            TryCloseHeaderFlyout(driver);
            return true;

        }

        internal bool SetHeaderValue(LookupItem control)
        {
            var controlName = control.Name;
            bool isHeader = true;
            bool removeAll = true;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.LookupFieldContainer].Replace("[NAME]", controlName);
            return ExecuteInHeaderContainer(driver, xpathToContainer,
                    fieldContainer =>
                    {
                        TryRemoveLookupValue(driver, fieldContainer, control, removeAll, isHeader);
                        TrySetValue(driver, fieldContainer, control);

                        TryCloseHeaderFlyout(driver);
                        return true;
                    });
        }

        internal bool SetHeaderValue(LookupItem[] controls, bool clearFirst = true)
        {
            var control = controls.First();
            var controlName = control.Name;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.LookupFieldContainer].Replace("[NAME]", controlName);
            return ExecuteInHeaderContainer(driver, xpathToContainer,
                    container =>
                    {
                        if (clearFirst)
                            TryRemoveLookupValue(driver, container, control);

                        TryToSetValue(driver, container, controls);

                        TryCloseHeaderFlyout(driver);
                        return true;
                    });
        }

        internal bool SetHeaderValue(OptionSet control)
        {
            var controlName = control.Name;
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.OptionSetFieldContainer].Replace("[NAME]", controlName);
            return ExecuteInHeaderContainer(driver, xpathToContainer,
                    container =>
                    {
                        TrySetValue(container, control);

                        TryCloseHeaderFlyout(driver);
                        return true;
                    });
        }

        internal bool SetHeaderValue(MultiValueOptionSet control)
        {
            TryExpandHeaderFlyout(driver);

            SetValue(control, FormContextType.Header);

            TryCloseHeaderFlyout(driver);
            return true;
        }

        internal bool SetHeaderValue(BooleanItem control)
        {
            TryExpandHeaderFlyout(driver);

            SetValue(control, FormContextType.Header);

            TryCloseHeaderFlyout(driver);
            return true;
        }

        internal bool SetHeaderValue(string field, DateTime value, string formatDate = null, string formatTime = null)
        {
            var control = new DateTimeControl(field)
            {
                Value = value,
                DateFormat = formatDate,
                TimeFormat = formatTime
            };
            return SetHeaderValue(control);
        }

        internal bool SetHeaderValue(DateTimeControl control)
            => TrySetHeaderValue(driver, control);

        internal bool ClearHeaderValue(DateTimeControl control)
        {
            var controlName = control.Name;
            return TrySetHeaderValue(driver, new DateTimeControl(controlName));
        }

        private bool TrySetHeaderValue(IWebDriver driver, DateTimeControl control)
        {
            var xpathToContainer = AppElements.Xpath[AppReference.Entity.Header.DateTimeFieldContainer].Replace("[NAME]", control.Name);
            return ExecuteInHeaderContainer(driver, xpathToContainer,
                container => TrySetValue(driver, container, control, FormContextType.Header));
        }

        internal bool ClearValue(DateTimeControl control, FormContextType formContextType)
            => TrySetValue(driver, container: driver, control: new DateTimeControl(control.Name), formContextType); // Pass an empty control

        internal bool ClearValue(string fieldName, FormContextType formContextType)
        {
            SetValue(fieldName, string.Empty, formContextType);

            return true;
        }

        internal bool ClearValue(LookupItem control, FormContextType formContextType, bool removeAll = true)
        {
            var controlName = control.Name;
            var fieldContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldLookupFieldContainer].Replace("[NAME]", controlName)));
            TryRemoveLookupValue(driver, fieldContainer, control, removeAll);
            return true;
        }

        private static void TryRemoveLookupValue(IWebDriver driver, IWebElement fieldContainer, LookupItem control, bool removeAll = true, bool isHeader = false)
        {
            var controlName = control.Name;
            fieldContainer.Hover(driver);

            var xpathDeleteExistingValues = By.XPath(AppElements.Xpath[AppReference.Entity.LookupFieldDeleteExistingValue].Replace("[NAME]", controlName));
            var existingValues = fieldContainer.FindElements(xpathDeleteExistingValues);

            var xpathToExpandButton = By.XPath(AppElements.Xpath[AppReference.Entity.LookupFieldExpandCollapseButton].Replace("[NAME]", controlName));
            bool success = fieldContainer.TryFindElement(xpathToExpandButton, out var expandButton);
            if (success)
            {
                expandButton.Click(true);

                var count = existingValues.Count;
                fieldContainer.WaitUntil(x => x.FindElements(xpathDeleteExistingValues).Count > count);
            }

            fieldContainer.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldLookupSearchButton].Replace("[NAME]", controlName)));

            existingValues = fieldContainer.FindElements(xpathDeleteExistingValues);
            if (existingValues.Count == 0)
                return;

            if (removeAll)
            {
                // Removes all selected items

                while (existingValues.Count > 0)
                {
                    foreach (var v in existingValues)
                        v.Click(true);

                    existingValues = fieldContainer.FindElements(xpathDeleteExistingValues);
                }

                return;
            }

            // Removes an individual item by value or index
            var value = control.Value;
            if (value == null)
                throw new InvalidOperationException($"No value or index has been provided for the LookupItem {controlName}. Please provide an value or an empty string or an index and try again.");

            if (value == string.Empty)
            {
                var index = control.Index;
                if (index >= existingValues.Count)
                    throw new InvalidOperationException($"Field '{controlName}' does not contain {index + 1} records. Please provide an index value less than {existingValues.Count}");

                existingValues[index].Click(true);
                return;
            }

            var existingValue = existingValues.FirstOrDefault(v => v.GetAttribute("aria-label").EndsWith(value));
            if (existingValue == null)
                throw new InvalidOperationException($"Field '{controlName}' does not contain a record with the name:  {value}");

            existingValue.Click(true);
            driver.WaitForTransaction();
        }

        internal bool ClearValue(OptionSet control, FormContextType formContextType)
        {
            control.Value = "-1";
            SetValue(control, formContextType);

            return true;
        }

        internal bool ClearValue(MultiValueOptionSet control, FormContextType formContextType)
        {
            RemoveMultiOptions(control, formContextType);

            return true;
        }

        internal bool SelectForm(string formName)
        {
            driver.WaitForTransaction();

            if (!driver.HasElement(By.XPath(Elements.Xpath[Reference.Entity.FormSelector])))
                throw new NotFoundException("Unable to find form selector on the form");

            var formSelector = driver.WaitUntilAvailable(By.XPath(Elements.Xpath[Reference.Entity.FormSelector]));
            // Click didn't work with IE
            formSelector.SendKeys(Keys.Enter);

            driver.WaitUntilVisible(By.XPath(Elements.Xpath[Reference.Entity.FormSelectorFlyout]));

            var flyout = driver.FindElement(By.XPath(Elements.Xpath[Reference.Entity.FormSelectorFlyout]));
            var forms = flyout.FindElements(By.XPath(Elements.Xpath[Reference.Entity.FormSelectorItem]));

            var form = forms.FirstOrDefault(a => a.GetAttribute("data-text").EndsWith(formName, StringComparison.OrdinalIgnoreCase));
            if (form == null)
                throw new NotFoundException($"Form {formName} is not in the form selector");

            driver.ClickWhenAvailable(By.Id(form.GetAttribute("id")));

            driver.WaitForPageToLoad();
            driver.WaitForTransaction();

            return true;
        }

        internal bool AddValues(LookupItem[] controls)
        {

            SetValue(controls, FormContextType.Entity, false);

            return true;

        }

        internal bool RemoveValues(LookupItem[] controls)
        {

            foreach (var control in controls)
                ClearValue(control, FormContextType.Entity, false);

            return true;

        }

        internal TResult ExecuteInHeaderContainer<TResult>(IWebDriver driver, string xpathToContainer, Func<IWebElement, TResult> function)
        {
            TResult lookupValue = default(TResult);

            TryExpandHeaderFlyout(driver);

            var xpathToFlyout = AppElements.Xpath[AppReference.Entity.Header.Flyout];
            driver.WaitUntilVisible(By.XPath(xpathToFlyout), TimeSpan.FromSeconds(5),
                flyout =>
                {
                    IWebElement container = flyout.FindElement(By.XPath(xpathToContainer));
                    lookupValue = function(container);
                });

            return lookupValue;
        }

        internal void TryExpandHeaderFlyout(IWebDriver driver)
        {
            driver.WaitUntilAvailable(
                By.XPath(AppElements.Xpath[AppReference.Entity.Header.Container]),
                "Unable to find header on the form");

            var xPath = By.XPath(AppElements.Xpath[AppReference.Entity.Header.FlyoutButton]);
            var headerFlyoutButton = driver.FindElement(xPath);
            bool expanded = bool.Parse(headerFlyoutButton.GetAttribute("aria-expanded"));

            if (!expanded)
                headerFlyoutButton.Click(true);
        }

        internal void TryCloseHeaderFlyout(IWebDriver driver)
        {
            bool hasHeader = driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Entity.Header.Container]));
            if (!hasHeader)
                throw new NotFoundException("Unable to find header on the form");

            var xPath = By.XPath(AppElements.Xpath[AppReference.Entity.Header.FlyoutButton]);
            var headerFlyoutButton = driver.FindElement(xPath);
            bool expanded = bool.Parse(headerFlyoutButton.GetAttribute("aria-expanded"));

            if (expanded)
                headerFlyoutButton.Click(true);
        }

        #endregion

        #region Lookup 

        internal bool OpenLookupRecord(int index)
        {
            driver.WaitForTransaction();

            var rows = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.Lookup.LookupResultRows]));
            if (!rows.Any())
            {
                throw new NotFoundException("No rows found");
            }

            rows.ElementAt(index).Click();
            driver.WaitForTransaction();

            return true;
        }

        internal bool SearchLookupField(LookupItem control, string searchCriteria)
        {

            //Click in the field and enter values
            control.Value = searchCriteria;
            SetValue(control, FormContextType.Entity);

            driver.WaitForTransaction();

            return true;
        }

        internal bool SelectLookupRelatedEntity(string entityName)
        {
            //Click the Related Entity on the Lookup Flyout

            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Lookup.RelatedEntityLabel].Replace("[NAME]", entityName))))
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Lookup.RelatedEntityLabel].Replace("[NAME]", entityName))).Click(true);
            else
                throw new NotFoundException($"Lookup Entity {entityName} not found");

            driver.WaitForTransaction();

            return true;
        }

        internal bool SwitchLookupView(string viewName)
        {

            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Lookup.ChangeViewButton])))
            {
                //Click Change View 
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Lookup.ChangeViewButton])).Click(true);

                driver.WaitForTransaction();

                //Click View Requested 
                var rows = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.Lookup.ViewRows]));
                if (rows.Any(x => x.Text.Equals(viewName, StringComparison.OrdinalIgnoreCase)))
                    rows.First(x => x.Text.Equals(viewName, StringComparison.OrdinalIgnoreCase)).Click(true);
                else
                    throw new NotFoundException($"View {viewName} not found");
            }

            else
                throw new NotFoundException("Lookup menu not visible");

            driver.WaitForTransaction();
            return true;
        }

        internal bool SelectLookupNewButton()
        {

            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Lookup.NewButton])))
            {
                var newButton = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Lookup.NewButton]));

                if (newButton.GetAttribute("disabled") == null)
                    driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Lookup.NewButton])).Click();
                else
                    throw new ElementNotInteractableException("New button is not enabled.  If this is a mulit-entity lookup, please use SelectRelatedEntity first.");
            }
            else
                throw new NotFoundException("New button not found.");

            driver.WaitForTransaction();

            return true;

        }

        internal IReadOnlyList<FormNotification> GetFormNotifications()
        {

            List<FormNotification> notifications = new List<FormNotification>();

            // Look for notificationMessageAndButtons bar
            var notificationMessage = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormMessageBar]), TimeSpan.FromSeconds(2));

            if (notificationMessage != null)
            {
                IWebElement icon = null;

                try
                {
                    icon = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FormMessageBarTypeIcon]));
                }
                catch (NoSuchElementException)
                {
                    // Swallow the exception
                }

                if (icon != null)
                {
                    var notification = new FormNotification
                    {
                        Message = notificationMessage?.Text
                    };
                    string classes = icon.GetAttribute("class");
                    notification.SetTypeFromClass(classes);
                    notifications.Add(notification);
                }
            }

            // Look for the notification wrapper, if it doesn't exist there are no notificatios
            var notificationBar = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Entity.FormNotifcationBar]), TimeSpan.FromSeconds(2));
            if (notificationBar == null)
                return notifications;
            else
            {
                // If there are multiple notifications, the notifications must be expanded first.
                if (notificationBar.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FormNotifcationExpandButton]), out var expandButton))
                {
                    if (!Convert.ToBoolean(notificationBar.GetAttribute("aria-expanded")))
                        expandButton.Click();

                    // After expansion the list of notifications are now in a different element
                    notificationBar = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormNotifcationFlyoutRoot]), TimeSpan.FromSeconds(2), "Failed to open the form notifications");
                }

                var notificationList = notificationBar.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FormNotifcationList]));
                var notificationListItems = notificationList.FindElements(By.TagName("li"));

                foreach (var item in notificationListItems)
                {
                    var icon = item.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.FormNotifcationTypeIcon]));

                    var notification = new FormNotification
                    {
                        Message = item.Text
                    };
                    string classes = icon.GetAttribute("class");
                    notification.SetTypeFromClass(classes);
                    notifications.Add(notification);
                }

                if (notificationBar != null)
                {
                    notificationBar = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Entity.FormNotifcationBar]), TimeSpan.FromSeconds(2));
                    notificationBar.Click(true); // Collapse the notification bar
                }
                return notifications;
            }
        }

        #endregion

        #region Timeline

        /// <summary>
        /// This method opens the popout menus in the Dynamics 365 pages. 
        /// This method uses a thinktime since after the page loads, it takes some time for the 
        /// widgets to load before the method can find and popout the menu.
        /// </summary>
        /// <param name="popoutName">The By Object of the Popout menu</param>
        /// <param name="popoutItemName">The By Object of the Popout Item name in the popout menu</param>
        /// <param name="thinkTime">Amount of time(milliseconds) to wait before this method will click on the "+" popout menu.</param>
        /// <returns>True on success, False on failure to invoke any action</returns>
        internal bool OpenAndClickPopoutMenu(By menuName, By menuItemName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(menuName);
            try
            {
                driver.ClickWhenAvailable(menuItemName);
            }
            catch
            {
                // Element is stale reference is thrown here since the HTML components 
                // get destroyed and thus leaving the references null. 
                // It is expected that the components will be destroyed and the next 
                // action should take place after it and hence it is ignored.
                return false;
            }

            return true;

        }

        internal bool Delete(int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var deleteBtn = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.Delete]),
                "Delete Button is not available");

            deleteBtn?.Click();
            ConfirmationDialog(true);

            driver.WaitForTransaction();

            return true;
        }

        internal bool Assign(string userOrTeamToAssign, int thinkTime = Constants.DefaultThinkTime)
        {
            //Click the Assign Button on the Entity Record
            ThinkTime(thinkTime);
            var assignBtn = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.Assign]),
                "Assign Button is not available");

            assignBtn?.Click();
            AssignDialog(Dialogs.AssignTo.User, userOrTeamToAssign);

            return true;
        }

        internal bool SwitchProcess(string processToSwitchTo, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.ProcessButton]), TimeSpan.FromSeconds(5));

            driver.ClickWhenAvailable(
                By.XPath(AppElements.Xpath[AppReference.Entity.SwitchProcess]),
                TimeSpan.FromSeconds(5),
                "The Switch Process Button is not available."
            );

            return true;
        }

        internal bool CloseActivity(bool closeOrCancel, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            var xPathQuery = closeOrCancel
                ? AppElements.Xpath[AppReference.Dialogs.CloseActivity.Close]
                : AppElements.Xpath[AppReference.Dialogs.CloseActivity.Cancel];

            var action = closeOrCancel ? "Close" : "Cancel";

            var dialog = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]));

            var actionButton = dialog.FindElement(By.XPath(xPathQuery));

            actionButton?.Click();

            driver.WaitForTransaction();

            return true;
        }

        internal bool CloseOpportunity(bool closeAsWon, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            var xPathQuery = closeAsWon
                ? AppElements.Xpath[AppReference.Entity.CloseOpportunityWin]
                : AppElements.Xpath[AppReference.Entity.CloseOpportunityLoss];

            var closeBtn = driver.WaitUntilAvailable(By.XPath(xPathQuery), "Opportunity Close Button is not available");

            closeBtn?.Click();
            driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.Dialogs.CloseOpportunity.Ok]));
            CloseOpportunityDialog(true);

            return true;
        }

        internal bool CloseOpportunity(double revenue, DateTime closeDate, string description, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);

            //SetValue(Elements.ElementId[AppReference.Dialogs.CloseOpportunity.ActualRevenueId], revenue.ToString(CultureInfo.CurrentCulture));
            //SetValue(Elements.ElementId[AppReference.Dialogs.CloseOpportunity.CloseDateId], closeDate);
            //SetValue(Elements.ElementId[AppReference.Dialogs.CloseOpportunity.DescriptionId], description);

            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Dialogs.CloseOpportunity.Ok]),
                    TimeSpan.FromSeconds(5),
                    "The Close Opportunity dialog is not available."
                    );

            return true;
        }

        /// <summary>
        /// This method opens the popout menus in the Dynamics 365 pages. 
        /// This method uses a thinktime since after the page loads, it takes some time for the 
        /// widgets to load before the method can find and popout the menu.
        /// </summary>
        /// <param name="popoutName">The name of the Popout menu</param>
        /// <param name="popoutItemName">The name of the Popout Item name in the popout menu</param>
        /// <param name="thinkTime">Amount of time(milliseconds) to wait before this method will click on the "+" popout menu.</param>
        /// <returns>True on success, False on failure to invoke any action</returns>
        internal bool OpenAndClickPopoutMenu(string popoutName, string popoutItemName, int thinkTime = Constants.DefaultThinkTime)
        {
            return this.OpenAndClickPopoutMenu(By.XPath(Elements.Xpath[popoutName]), By.XPath(Elements.Xpath[popoutItemName]), thinkTime);
        }


        /// <summary>
        /// Provided a By object which represents a HTML Button object, this method will
        /// find it and click it.
        /// </summary>
        /// <param name="by">The object of Type By which represents a HTML Button object</param>
        /// <returns>True on success, False/Exception on failure to invoke any action</returns>
        internal bool ClickButton(By by)
        {
            var button = driver.WaitUntilAvailable(by);
            if (button.TagName.Equals("button"))
            {
                try
                {
                    driver.ClickWhenAvailable(by);
                }
                catch
                {
                    // Element is stale reference is thrown here since the HTML components 
                    // get destroyed and thus leaving the references null. 
                    // It is expected that the components will be destroyed and the next 
                    // action should take place after it and hence it is ignored.
                }

                return true;
            }
            else if (button.FindElements(By.TagName("button")).Any())
            {
                button.FindElements(By.TagName("button")).First().Click();
                return true;
            }
            else
            {
                throw new InvalidOperationException($"Control does not exist");
            }
        }

        /// <summary>
        /// Provided a fieldname as a XPath which represents a HTML Button object, this method will
        /// find it and click it.
        /// </summary>
        /// <param name="fieldNameXpath">The field as a XPath which represents a HTML Button object</param>
        /// <returns>True on success, Exception on failure to invoke any action</returns>
        internal bool ClickButton(string fieldNameXpath)
        {
            try
            {
                return ClickButton(By.XPath(fieldNameXpath));
            }
            catch (Exception e)
            {
                throw new InvalidOperationException($"Field: {fieldNameXpath} with Does not exist", e);
            }
        }

        /// <summary>
        /// Generic method to help click on any item which is clickable or uniquely discoverable with a By object.
        /// </summary>
        /// <param name="by">The xpath of the HTML item as a By object</param>
        /// <returns>True on success, Exception on failure to invoke any action</returns>
        internal bool SelectTab(string tabName, string subTabName = "", int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            IWebElement tabList;
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext])))
            {
                var dialogContainer = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Dialogs.DialogContext]));
                tabList = dialogContainer.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TabList]));
            }
            else
            {
                tabList = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TabList]));
            }

            ClickTab(tabList, AppElements.Xpath[AppReference.Entity.Tab], tabName);

            //Click Sub Tab if provided
            if (!String.IsNullOrEmpty(subTabName))
            {
                ClickTab(tabList, AppElements.Xpath[AppReference.Entity.SubTab], subTabName);
            }

            driver.WaitForTransaction();
            return true;
        }

        internal void ClickTab(IWebElement tabList, string xpath, string name)
        {
            IWebElement moreTabsButton;
            IWebElement listItem;
            // Look for the tab in the tab list, else in the more tabs menu
            IWebElement searchScope = null;
            if (tabList.HasElement(By.XPath(string.Format(xpath, name))))
            {
                searchScope = tabList;
            }
            else if (tabList.TryFindElement(By.XPath(AppElements.Xpath[AppReference.Entity.MoreTabs]), out moreTabsButton))
            {
                moreTabsButton.Click();

                // No tab to click - subtabs under 'Related' are automatically expanded in overflow menu
                if (name == "Related")
                {
                    return;
                }
                else
                {
                    searchScope = driver.FindElement(By.XPath(AppElements.Xpath[AppReference.Entity.MoreTabsMenu]));
                }
            }

            if (searchScope.TryFindElement(By.XPath(string.Format(xpath, name)), out listItem))
            {
                listItem.Click(true);
            }
            else
            {
                throw new Exception($"The tab with name: {name} does not exist");
            }
        }

        /// <summary>
        /// A generic setter method which will find the HTML Textbox/Textarea object and populate
        /// it with the value provided. The expected tag name is to make sure that it hits
        /// the expected tag and not some other object with the similar fieldname.
        /// </summary>
        /// <param name="fieldName">The name of the field representing the HTML Textbox/Textarea object</param>
        /// <param name="value">The string value which will be populated in the HTML Textbox/Textarea</param>
        /// <param name="expectedTagName">Expected values - textbox/textarea</param>
        /// <returns>True on success, Exception on failure to invoke any action</returns>
        internal bool SetValue(string fieldName, string value, string expectedTagName)
        {
            var inputbox = driver.WaitUntilAvailable(By.XPath(Elements.Xpath[fieldName]));
            if (expectedTagName.Equals(inputbox.TagName, StringComparison.InvariantCultureIgnoreCase))
            {
                if (!inputbox.TagName.Contains("iframe", StringComparison.InvariantCultureIgnoreCase))
                {
                    inputbox.Click(true);
                    inputbox.Clear();
                    inputbox.SendKeys(value);
                }
                else
                {
                    driver.SwitchTo().Frame(inputbox);

                    driver.WaitUntilAvailable(By.TagName("iframe"));
                    driver.SwitchTo().Frame(0);

                    var inputBoxBody = driver.WaitUntilAvailable(By.TagName("body"));
                    inputBoxBody.Click(true);
                    inputBoxBody.SendKeys(value);

                    driver.SwitchTo().DefaultContent();
                }

                return true;
            }

            throw new InvalidOperationException($"Field: {fieldName} with tagname {expectedTagName} Does not exist");
        }

        #endregion

        #region BusinessProcessFlow

        internal Field BPFGetField(string field)
        {
            // Initialize the Business Process Flow context
            var formContext = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFormContext]));
            var fieldElement = formContext.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.FieldSectionItemContainer].Replace("[NAME]", field)));
            Field returnField = new Field(fieldElement);
            returnField.Name = field;

            IWebElement fieldLabel = null;
            try
            {
                fieldLabel = fieldElement.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.TextFieldLabel].Replace("[NAME]", field)));
            }
            catch (NoSuchElementException)
            {
                // Swallow
            }

            if (fieldLabel != null)
            {
                returnField.Label = fieldLabel.Text;
            }

            return returnField;

        }

        /// <summary>
        /// Set Value
        /// </summary>
        /// <param name="field">The field</param>
        /// <param name="value">The value</param>
        /// <example>xrmApp.BusinessProcessFlow.SetValue("firstname", "Test");</example>
        internal bool BPFSetValue(string field, string value)
        {
            var fieldContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.TextFieldContainer].Replace("[NAME]", field)));

            if (fieldContainer.FindElements(By.TagName("input")).Count > 0)
            {
                var input = fieldContainer.FindElement(By.TagName("input"));
                if (input != null)
                {
                    input.Click(true);
                    input.Clear();
                    input.SendKeys(value, true);
                    input.SendKeys(Keys.Tab);
                }
            }
            else if (fieldContainer.FindElements(By.TagName("textarea")).Count > 0)
            {
                var textarea = fieldContainer.FindElement(By.TagName("textarea"));
                textarea.Click();
                textarea.Clear();
                textarea.SendKeys(value);
            }
            else
            {
                throw new Exception($"Field with name {field} does not exist.");
            }

            return true;
        }

        /// <summary>
        /// Sets the value of a picklist.
        /// </summary>
        /// <param name="option">The option you want to set.</param>
        /// <example>xrmBrowser.BusinessProcessFlow.SetValue(new OptionSet { Name = "preferredcontactmethodcode", Value = "Email" });</example>
        public bool BPFSetValue(OptionSet option)
        {
            var fieldContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.TextFieldContainer].Replace("[NAME]", option.Name)));

            if (fieldContainer.FindElements(By.TagName("select")).Count > 0)
            {
                var select = fieldContainer.FindElement(By.TagName("select"));
                var options = select.FindElements(By.TagName("option"));

                foreach (var op in options)
                {
                    if (op.Text != option.Value && op.GetAttribute("value") != option.Value) continue;
                    op.Click(true);
                    break;
                }
            }
            else
            {
                throw new InvalidOperationException($"Field: {option.Name} Does not exist");
            }

            return true;
        }

        /// <summary>
        /// Sets the value of a Boolean Item.
        /// </summary>
        /// <param name="option">The option you want to set.</param>
        /// <example>xrmBrowser.BusinessProcessFlow.SetValue(new BooleanItem { Name = "preferredcontactmethodcode"});</example>
        public bool BPFSetValue(BooleanItem option)
        {
            var fieldContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BooleanFieldContainer].Replace("[NAME]", option.Name)));
            var selectedOption = fieldContainer.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BooleanFieldSelectedOption].Replace("[NAME]", option.Name)));

            var existingValue = selectedOption.GetAttribute<string>("Title") == "Yes";
            if (option.Value != existingValue)
            {
                fieldContainer.Click();
            }

            return true;
        }

        /// <summary>
        /// Sets the value of a Date Field.
        /// </summary>
        /// <param name="field">The field id or name.</param>
        /// <param name="date">DateTime value.</param>
        /// <param name="format">DateTime format</param>
        /// <example> xrmBrowser.BusinessProcessFlow.SetValue("birthdate", DateTime.Parse("11/1/1980"));</example>
        public bool BPFSetValue(string field, DateTime date, string format = "MM dd yyyy")
        {
            var dateField = AppElements.Xpath[AppReference.BusinessProcessFlow.DateTimeFieldContainer].Replace("[FIELD]", field);

            if (driver.HasElement(By.XPath(dateField)))
            {
                var fieldElement = driver.ClickWhenAvailable(By.XPath(dateField));

                if (fieldElement.GetAttribute("value").Length > 0)
                {
                    //fieldElement.Click();
                    //fieldElement.SendKeys(date.ToString(format));
                    //fieldElement.SendKeys(Keys.Enter);

                    fieldElement.Click();
                    ThinkTime(250);
                    fieldElement.Click();
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Backspace);
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Backspace);
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Backspace);
                    ThinkTime(250);
                    fieldElement.SendKeys(date.ToString(format), true);
                    ThinkTime(500);
                    fieldElement.SendKeys(Keys.Tab);
                    ThinkTime(250);
                }
                else
                {
                    fieldElement.Click();
                    ThinkTime(250);
                    fieldElement.Click();
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Backspace);
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Backspace);
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Backspace);
                    ThinkTime(250);
                    fieldElement.SendKeys(date.ToString(format));
                    ThinkTime(250);
                    fieldElement.SendKeys(Keys.Tab);
                    ThinkTime(250);
                }
            }
            else
                throw new InvalidOperationException($"Field: {field} Does not exist");

            return true;
        }

        internal bool NextStage(string stageName, Field businessProcessFlowField = null, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            //Find the Business Process Stages
            var processStages = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.NextStage_UCI]));

            if (processStages.Count == 0)
                return true;

            foreach (var processStage in processStages)
            {
                var divs = processStage.FindElements(By.TagName("div"));

                //Click the Label of the Process Stage if found
                foreach (var div in divs)
                {
                    if (div.Text.Equals(stageName, StringComparison.OrdinalIgnoreCase))
                    {
                        div.Click();
                    }
                }
            }

            var flyoutFooterControls = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.Flyout_UCI]));

            foreach (var control in flyoutFooterControls)
            {
                //If there's a field to enter, fill it out
                if (businessProcessFlowField != null)
                {
                    var bpfField = control.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.BusinessProcessFlowFieldName].Replace("[NAME]", businessProcessFlowField.Name)));

                    if (bpfField != null)
                    {
                        bpfField.Click();
                        for (int i = 0; i < businessProcessFlowField.Value.Length; i++)
                        {
                            bpfField.SendKeys(businessProcessFlowField.Value.Substring(i, 1));
                        }
                    }
                }

                //Click the Next Stage Button
                var nextButton = control.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.NextStageButton]));
                nextButton.Click();
            }

            return true;
        }

        internal bool SelectStage(string stageName, int thinkTime = Constants.DefaultThinkTime)
        {
            //Find the Business Process Stages
            var processStages = driver.FindElements(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.NextStage_UCI]));

            foreach (var processStage in processStages)
            {
                var divs = processStage.FindElements(By.TagName("div"));

                //Click the Label of the Process Stage if found
                foreach (var div in divs)
                {
                    if (div.Text.Equals(stageName, StringComparison.OrdinalIgnoreCase))
                    {
                        div.Click();
                    }
                }
            }

            driver.WaitForTransaction();

            return true;
        }

        internal bool SetActive(string stageName = "", int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            if (!String.IsNullOrEmpty(stageName))
            {
                SelectStage(stageName);

                if (!driver.HasElement(By.XPath("//button[contains(@data-id,'setActiveButton')]")))
                    throw new NotFoundException($"Unable to find the Set Active button. Please verify the stage name {stageName} is correct.");

                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.SetActiveButton])).Click(true);

                driver.WaitForTransaction();
            }

            return true;
        }

        internal bool BPFPin(string stageName, int thinkTime = Constants.DefaultThinkTime)
        {

            //Click the BPF Stage
            SelectStage(stageName, 0);
            driver.WaitForTransaction();

            //Pin the Stage
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.PinStageButton])))
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.PinStageButton])).Click();
            else
                throw new NotFoundException($"Pin button for stage {stageName} not found.");

            driver.WaitForTransaction();
            return true;
        }

        internal bool BPFClose(string stageName, int thinkTime = Constants.DefaultThinkTime)
        {
            //Click the BPF Stage
            SelectStage(stageName, 0);
            driver.WaitForTransaction();

            //Pin the Stage
            if (driver.HasElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.CloseStageButton])))
                driver.FindElement(By.XPath(AppElements.Xpath[AppReference.BusinessProcessFlow.CloseStageButton])).Click(true);
            else
                throw new NotFoundException($"Close button for stage {stageName} not found.");

            driver.WaitForTransaction();
            return true;
        }

        #endregion

        #region GlobalSearch

        /// <summary>
        /// Searches for the specified criteria in Global Search.
        /// </summary>
        /// <param name="criteria">Search criteria.</param>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param> time.</param>
        /// <example>xrmBrowser.GlobalSearch.Search("Contoso");</example>
        internal bool GlobalSearch(string criteria, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Navigation.SearchButton]),
                TimeSpan.FromSeconds(5),
                "The Global Search button is not available.");

            var input = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Text]), "The Global Search text field is not available.");

            string reference = null;
            driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Type]),
                e =>
                {
                    var searchType = e.GetAttribute("value");
                    reference =
                        searchType == "0" ? AppReference.GlobalSearch.RelevanceSearchButton :
                        searchType == "1" ? AppReference.GlobalSearch.CategorizedSearchButton :
                        throw new InvalidOperationException("The Global Search type is not available.");
                },
                "The Global Search type is not available."
            );

            IWebElement button = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[reference]), "The Global Search Button is not available.");

            input.SendKeys(criteria, true);
            button.Click(true);
            return true;
        }

        /// <summary>
        /// Filter by entity in the Global Search Results.
        /// </summary>
        /// <param name="entity">The entity you want to filter with.</param>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param>
        /// <example>xrmBrowser.GlobalSearch.FilterWith("Account");</example>
        public bool FilterWith(string entity, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Filter]),
                TimeSpan.FromSeconds(10),
                picklist =>
                {
                    var options = picklist.FindElements(By.TagName("option"));
                    var option = options.FirstOrDefault(x => x.Text == entity);
                    if (option == null)
                        throw new InvalidOperationException($"Entity '{entity}' does not exist in the Filter options.");

                    picklist.Click();
                    option.Click();
                },
                "Filter With picklist is not available. The timeout period elapsed waiting for the picklist to be available."
            );
            return true;
        }

        /// <summary>
        /// Filter by group and value in the Global Search Results.
        /// </summary>
        /// <param name="filterby">The Group that contains the filter you want to use.</param>
        /// <param name="value">The value listed in the group by area.</param>
        /// <example>xrmBrowser.GlobalSearch.Filter("Record Type", "Accounts");</example>
        public bool Filter(string filterBy, string value, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var xpathToContainer = By.XPath(AppElements.Xpath[AppReference.GlobalSearch.GroupContainer].Replace("[NAME]", filterBy));
            var xpathToValue = By.XPath(AppElements.Xpath[AppReference.GlobalSearch.FilterValue].Replace("[NAME]", value));
            driver.WaitUntilVisible(xpathToContainer,
                TimeSpan.FromSeconds(10),
                groupContainer => groupContainer.ClickWhenAvailable(xpathToValue, $"Filter By Value '{value}' does not exist in the Filter options."),
                "Filter With picklist is not available. The timeout period elapsed waiting for the picklist to be available."
            );
            return true;
        }

        /// <summary>
        /// Opens the specified record in the Global Search Results.
        /// </summary>
        /// <param name="entity">The entity you want to open a record.</param>
        /// <param name="index">The index of the record you want to open.</param>
        /// <param name="thinkTime">Used to simulate a wait time between human interactions. The Default is 2 seconds.</param> time.</param>
        /// <example>xrmBrowser.GlobalSearch.OpenRecord("Accounts",0);</example>
        public bool OpenGlobalSearchRecord(string entity, int index, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            var searchTypeElement = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Type]), "The Global Search type is not available.");
            var searchType = searchTypeElement.GetAttribute("value");

            if (searchType == "1") //Categorized Search
            {
                var resultsContainer = driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Container]),
                    Constants.DefaultTimeout,
                    "Search Results is not available"
                );

                var entityContainer = resultsContainer.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.EntityContainer].Replace("[NAME]", entity)),
                    $"Entity {entity} was not found in the results"
                );

                var records = entityContainer.FindElements(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Records]));
                if (records == null || records.Count == 0)
                    throw new InvalidOperationException($"No records found for entity {entity}");

                if (index >= records.Count)
                    throw new InvalidOperationException($"There was less than {index} records in your the search result.");

                records[index].Click(true);

                driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.Entity.FormContext]),
                    TimeSpan.FromSeconds(30),
                    "CRM Record is Unavailable or not finished loading. Timeout Exceeded"
                );
                return true;
            }

            if (searchType == "0") //Relevance Search
            {
                var resultsContainer = driver.WaitUntilAvailable(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.RelevanceResultsContainer]));
                var records = resultsContainer.FindElements(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.RelevanceResults].Replace("[ENTITY]", entity.ToUpper())));

                if (index >= records.Count)
                    throw new InvalidOperationException($"There was less than {index} records in your the search result.");

                records[index].Click(true);
                return true;
            }

            return false;
        }


        /// <summary>
        /// Changes the search type used for global search
        /// </summary>
        /// <param name="type">The type of search that you want to do.</param>
        /// <example>xrmBrowser.GlobalSearch.ChangeSearchType("Categorized");</example>
        public bool ChangeSearchType(string type, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            driver.WaitUntilVisible(By.XPath(AppElements.Xpath[AppReference.GlobalSearch.Type]),
                Constants.DefaultTimeout,
                select =>
                {
                    var options = select.FindElements(By.TagName("option"));
                    var option = options.FirstOrDefault(x => x.Text.Trim() == type);
                    if (option == null)
                        return;

                    select.Click(true);
                    option.Click(true);
                },
                "Search Results is not available");
            return true;
        }

        #endregion

        #region Dashboard

        internal bool SelectDashboard(string dashboardName, int thinkTime = Constants.DefaultThinkTime)
        {
            ThinkTime(thinkTime);
            //Click the drop-down arrow
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Dashboard.DashboardSelector]));
            //Select the dashboard
            driver.ClickWhenAvailable(By.XPath(AppElements.Xpath[AppReference.Dashboard.DashboardItemUCI].Replace("[NAME]", dashboardName)));

            // Wait for Dashboard to load
            driver.WaitForTransaction();

            return true;
        }

        #endregion

        #region PerformanceCenter

        internal void EnablePerformanceCenter()
        {
            driver.Navigate().GoToUrl($"{driver.Url}&perf=true");
            driver.WaitForPageToLoad();
            driver.WaitForTransaction();
        }

        #endregion

        internal void ThinkTime(int milliseconds)
        {
            DateTime Tthen = DateTime.Now;
            do
            {
                Application.DoEvents();
            } while (Tthen.AddMilliseconds(milliseconds) > DateTime.Now);
        }

        internal void ThinkTime(TimeSpan timespan)
        {
            var secs = timespan.TotalMilliseconds;
            DateTime Tthen = DateTime.Now;
            do
            {
                Application.DoEvents();
            } while (Tthen.AddSeconds(secs) > DateTime.Now);
        }

        public void Dispose()
        {
            driver.Dispose();
        }
    }
}
