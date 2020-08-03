#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-access-log
  DataType = "app-activity"
  Conditions = ["""ext_category=ApplicationGatewayAccessLog""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """host":"({app}.*?[^\\])"""",
    """operationName":"({activity}.*?[^\\])"""",
    """originalHost":"({src_host}.*?[^\\])"""",
    """userAgent":"({user_agent}.*?[^\\])"""",
    """requestUri":"({request_uri}.*?[^\\])"""",
    """recievedBytes":"({bytes}\d+)""",
  ]
}
```