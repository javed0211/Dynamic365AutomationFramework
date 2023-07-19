using OneAutomationFramework.DataBase;
using OneAutomationFramework.Drivers;
using OneAutomationFramework.Drivers.Appium;
using OneAutomationFramework.Drivers.FlaUI;
using OneAutomationFramework.Drivers.Selenium;
using TechTalk.SpecFlow.Plugins;
using TechTalk.SpecFlow.UnitTestProvider;

[assembly:RuntimePlugin(typeof(RuntimePlugin))]
namespace OneAutomationFramework.Drivers
{
    public class RuntimePlugin : IRuntimePlugin
    {
        public void Initialize(RuntimePluginEvents runtimePluginEvents, RuntimePluginParameters runtimePluginParameters,
            UnitTestProviderConfiguration unitTestProviderConfiguration)
        {
            runtimePluginEvents.CustomizeScenarioDependencies += RuntimePluginEvents_CustomizeScenarioDependencies;
        }

        private void RuntimePluginEvents_CustomizeScenarioDependencies(object? sender,
            CustomizeScenarioDependenciesEventArgs e)
        {
            e.ObjectContainer.RegisterTypeAs<SeleniumConfiguration, ISeleniumConfiguration>();
            e.ObjectContainer.RegisterTypeAs<DriverInitialiser, IDriverInitialiser>();
            e.ObjectContainer.RegisterTypeAs<RestSharpConfiguration, IRestSharpConfiguration>();
            e.ObjectContainer.RegisterTypeAs<AppiumConfiguration, IAppiumConfiguration>();
            e.ObjectContainer.RegisterTypeAs<AppiumDriverInitialiser, IAppiumDriverInitialiser>();
            e.ObjectContainer.RegisterTypeAs<DBConfiguration, IDataBaseConfiguration>();
            e.ObjectContainer.RegisterTypeAs<FlaUIConfiguration, IFlaUIConfiguration>();

        }
    }
}