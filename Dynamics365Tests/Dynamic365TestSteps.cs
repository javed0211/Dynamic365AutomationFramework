using Microsoft.Dynamics365.UIAutomation.Api.UCI;
using OneAutomationFramework.Drivers.Selenium;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using TechTalk.SpecFlow;

namespace Dynamics365.Dynamics365Tests
{
    [Binding]
    public sealed class Dynamic365TestSteps
    {
        // For additional details on SpecFlow step definitions see https://go.specflow.org/doc-stepdef

        private readonly ScenarioContext _scenarioContext;
        SeleniumDriver _driver;
        public Dynamic365TestSteps(SeleniumDriver driver)
        {
            _driver = driver;
        }

        [Given(@"I create xrmapp client")]
        public void GivenICreateXrmappClient()
        {
            var client = new WebClient(_driver.Current);
            var xrmApp = new XrmApp(client);

            xrmApp.OnlineLogin.Login(new Uri("https://bupaentoat.crm4.dynamics.com/"));
        }
    }
}
