#### Parser Content
```Java
{
Name = azure-event-hub-audit-event
  DataType = "app-activity"
  Conditions = ["""ext_category=AuditEvent""" ]
  DataType = "app-activity"
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """\WrequestClientApplication=(|({app}.+?))(\s+\w+=|\s*$)""",
    """operationName":"({activity}.*?[^\\])"""",
    """resultSignature":"({result}.*?[^\\])"""",
    """resourceId":"({resource}.*?[^\\])"""",
    """requestUri":"({request_uri}.*?[^\\])"""",
    """callerIpAddress":"({src_ip}.*?[^\\])"""",
  ]
}
```