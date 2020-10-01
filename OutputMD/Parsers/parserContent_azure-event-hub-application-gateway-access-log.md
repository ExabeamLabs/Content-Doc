#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-access-log
  DataType = "app-activity"
  Conditions = ["""ext_category=ApplicationGatewayAccessLog""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """host":"({app}.+?[^\\])"""",
    """operationName":"({activity}.+?[^\\])"""",
    """originalHost":"(({src_ip}[A-Fa-f\d.:]+)|({src_host}.+?[^\\]))"""",
    """userAgent":"(-|({user_agent}[^"\\]+))\\*"""",
    """requestUri":"({request_uri}[^"]+)"""",
    """receivedBytes":"*({bytes_in}\d+)""",
    """sentBytes":"*({bytes_out}\d+)""",
    """\[Namespace:\s*({azure_event_hub_namespace}\S+) ; EventHub name:\s*({azure_event_hub_name}[\w-]+)""",
  ]
}
```