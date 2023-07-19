﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.


using Microsoft.Dynamics365.UIAutomation.Browser;
using OneAutomationFramework.Drivers.Selenium;
using System;
using System.Collections.Generic;
using TechTalk.SpecFlow;

namespace Microsoft.Dynamics365.UIAutomation.Api.UCI
{
    public class XrmApp
    {
        internal WebClient _client;
        internal ScenarioContext _scenarioContext;

        public XrmApp(WebClient client)
        {
            _client = client;
        }

        public OnlineLogin OnlineLogin => this.GetElement<OnlineLogin>(_client);
        public Navigation Navigation => this.GetElement<Navigation>(_client);
        public CommandBar CommandBar => this.GetElement<CommandBar>(_client);
        public Grid Grid => this.GetElement<Grid>(_client);
        public Entity Entity => this.GetElement<Entity>(_client);
        public Dialogs Dialogs => this.GetElement<Dialogs>(_client);
        public Timeline Timeline => this.GetElement<Timeline>(_client);
        public BusinessProcessFlow BusinessProcessFlow => this.GetElement<BusinessProcessFlow>(_client);
        public Dashboard Dashboard => this.GetElement<Dashboard>(_client);
        public RelatedGrid RelatedGrid => this.GetElement<RelatedGrid>(_client);

        public GlobalSearch GlobalSearch => this.GetElement<GlobalSearch>(_client);
        public QuickCreate QuickCreate => this.GetElement<QuickCreate>(_client);
        public Lookup Lookup => this.GetElement<Lookup>(_client);

        public T GetElement<T>(WebClient client)
            where T : Element
        {
            return (T)Activator.CreateInstance(typeof(T), new object[] { client });
        }

        public void ThinkTime(int milliseconds)
        {
            _client.ThinkTime(milliseconds);
        }
        public void ThinkTime(TimeSpan timespan)
        {
            _client.ThinkTime((int)timespan.TotalMilliseconds);
        }

        public void Dispose()
        {
            _client?.Dispose();
        }
    }
}
