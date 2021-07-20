#### Parser Content
```Java
{
Name = azure-event-hub-key-vault-auth
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"operationName":"Authentication"""", """MICROSOFT.KEYVAULT""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """(?i)({app}Microsoft.KeyVault)""",
    """operationName":"({event_name}[^"]{1,2000})"""",
    """resultSignature":"({result}[^"]{1,2000})"""",
    """resourceId":"({resource}[^"]{1,2000})"""",
    """requestUri":"({request_uri}[^"]{1,2000})"""",
    """callerIpAddress":"({src_ip}[^"]{1,2000})"""",
    """resultDescription":"({additional_info}[^"]{1,2000})"""",
    """claims\/upn":"({user_email}[^"]{1,2000})""",
    """"properties":.+?"id":"({object}[^"]{1,2000})"""
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```