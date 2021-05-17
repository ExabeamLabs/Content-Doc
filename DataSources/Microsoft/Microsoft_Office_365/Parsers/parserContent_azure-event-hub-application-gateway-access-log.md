#### Parser Content
```Java
{
Name = azure-event-hub-application-gateway-access-log
  DataType = "app-activity"
  Conditions = ["""CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"category":"ApplicationGatewayAccessLog"""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
    """host":"({app}[^"\\]{1,2000})\\*"""",
    """operationName":"({activity}.+?[^\\])"""",
    """originalHost":"(({src_ip}[A-Fa-f\d.:]{1,2000})|({src_host}.+?[^\\]))"""",
    """userAgent":"(-|({user_agent}[^"\\]{1,2000}))\\*"""",
    """requestUri":"({request_uri}[^"]{1,2000})"""",
    """receivedBytes":"{0,20}({bytes_in}\d{1,100})""",
    """sentBytes":"{0,20}({bytes_out}\d{1,100})""",
    """"httpMethod":"({method}[^"]{1,2000})""",
    """"httpStatus":({result_code}\d{1,100})""",
    """"httpVersion"{1,20}:"{1,20}({protocol}\w+)"""
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```