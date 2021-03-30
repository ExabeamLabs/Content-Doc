#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-access-log
  DataType = "app-activity"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"category":"ApplicationGatewayAccessLog"""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """host":"({app}[^"\\]+)\\*"""",
    """operationName":"({activity}.+?[^\\])"""",
    """originalHost":"(({src_ip}[A-Fa-f\d.:]+)|({src_host}.+?[^\\]))"""",
    """userAgent":"(-|({user_agent}[^"\\]+))\\*"""",
    """requestUri":"({request_uri}[^"]+)"""",
    """receivedBytes":"*({bytes_in}\d+)""",
    """sentBytes":"*({bytes_out}\d+)""",
    """"httpMethod":"({method}[^"]+)""",
    """"httpStatus":({result_code}\d+)""",
    """"httpVersion"+:"+({protocol}\w+)"""
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```