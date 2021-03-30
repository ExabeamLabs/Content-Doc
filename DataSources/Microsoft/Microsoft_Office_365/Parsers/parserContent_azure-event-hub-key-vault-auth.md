#### Parser Content
```Java
{
Name = azure-event-hub-key-vault-auth
  DataType = "app-login"
  Conditions = [ """CEF:""", """|Skyformation|SkyFormation Cloud Apps Security|""", """"operationName":"Authentication"""", """MICROSOFT.KEYVAULT""" ]
  Fields = ${MSParserTemplates.cef-azure-event-hub.Fields}[
     """(?i)({app}Microsoft.KeyVault)""",
    """operationName":"({event_name}[^"]+)"""",
    """resultSignature":"({result}[^"]+)"""",
    """resourceId":"({resource}[^"]+)"""",
    """requestUri":"({request_uri}[^"]+)"""",
    """callerIpAddress":"({src_ip}[^"]+)"""",
    """resultDescription":"({additional_info}[^"]+)"""",
    """claims\/upn":"({user_email}[^"]+)""",
    """"properties":.+?"id":"({object}[^"]+)"""
  ]
}
cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Microsoft Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [  """CEF:""",   """|Skyformation|SkyFormation Cloud Apps Security|""",   """destinationServiceName=Azure dproc=EventHub""" ]

```