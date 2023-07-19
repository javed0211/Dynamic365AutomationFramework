using Microsoft.Dynamics365.UIAutomation.Api.UCI;
using OneAutomationFramework.Drivers.Selenium;
using TechTalk.SpecFlow;

namespace Dynamics365.Dynamics365Tests
{
    [Binding]
    public sealed class Hooks1
    {
        
        public Hooks1()
        {
        
        }


        [BeforeScenario("@tag1")]
        public void BeforeScenarioWithTag()
        {

        }

        [BeforeScenario(Order = 1)]
        public void FirstBeforeScenario()
        {
            
        }

        [AfterScenario]
        public void AfterScenario()
        {
            //TODO: implement logic that has to run after executing each scenario
        }
    }
}