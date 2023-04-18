#### Parser Content
```Java
{
Name = azure-event-hub-key-vault-auth
  DataType = "app-login"
  Conditions = [ """destinationServiceName =Azure""", """"operationName":"Authentication"""", """MICROSOFT.KEYVAULT""" ]
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

cef-azure-event-hub = {
  Vendor = Microsoft
  Product = Azure
  Lms = Direct 
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d{1,100}Z [\w\-.]{1,2000} """,
      """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S{1,2000})""",
      """\Wdvc=({host}\S{1,2000})""",
      """\Wdvchost=({host}[\w\-.]{1,2000})""",
      """\Wact=({activity}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """([^\|]{0,2000}\|){5}({activity}[^\|]{1,2000})""",
      """\WflexString1=({activity}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\WdestinationServiceName =({app}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wfname=({object}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wmsg=({additional_info}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wduser=(anonymous|({user_email}[^@=]{1,2000}@[^@=]{1,2000}?)|({user}.+?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
      """\Wsuser=(anonymous|({user_email}[^@=]{1,2000}@[^@=\s]{1,2000})|({user}[^\s]{1,2000}))(\s{1,100}|\s{0,100}$)""",
      """\Wsuid=(anonymous|({user_email}[^@=]{1,2000}@[^@=]{1,2000}?)|({user}.+?))(\s{1,100}\w{1,100}=|\s{0,100}$)""",
      """\Woutcome=({outcome}[^=]{1,2000})\s{1,100}(\w{1,100}=|$)""",
      """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\Wshost=(|--|({src_host}[^=]{1,2000}))(\s{1,100}\w+=|\s{0,100}$)""",
      """"clientIP":"({src_ip}[A-Fa-f.\d]{1,2000})""",
      """"description":"({additional_info}[^"]{1,2000})""",
      """"identity".*?"claims".*?"name":"({user}[^"]{1,2000})"""",
      """"callerIpAddress":"({src_ip}[a-fA-F\d.:]{1,2000})"""",
      """Namespace:\s{0,100}(|({event_hub_namespace}[^\]]{1,2000}?))\s{0,100}[\];]""",
      """EventHub name:\s{0,100}(|({event_hub_name}[^\]]{1,2000}?))\s{0,100}\]""",
      """\[Namespace:\s{0,100}({host}\S{1,2000}) ; EventHub name:"""
  
}
```