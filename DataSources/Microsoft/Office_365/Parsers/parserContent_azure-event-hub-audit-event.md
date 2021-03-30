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
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```