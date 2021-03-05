#### Parser Content
```Java
{
Name = azure-event-hub-app-service-http-logs
  DataType = "web-activity"
  Conditions = ["""ext_category=AppServiceHTTPLogs""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """CsHost":"({app}.*?[^\\])"""",
    """Result":"({action}.*?[^\\])"""",
    """resourceId":"({resource}.*?[^\\])"""",
    """CsUriStem":"({uri_query}.*?[^\\])"""",
    """CIp":"({dest_ip}.*?[^\\])"""",
    """UserAgent":"(-|({user_agent}.*?[^\\]))"""",
    """category":"({activity}.*?[^\\])"""",
    """"CsMethod":"({method}[^"]+)"""
    """"SPort":"({port}\d+)"""
  ]
  DupFields = ["app->web_domain"]
}
```