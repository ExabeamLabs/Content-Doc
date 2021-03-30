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
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```