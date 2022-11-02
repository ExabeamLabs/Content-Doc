#### Parser Content
```Java
{
Name = microsoft-azure-network-connection-successful
  Vendor = Microsoft
  Product = Azure
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """destinationServiceName =Azure""", """"category":"AzureFirewallApplicationRule"""", """"resourceId":"""", """dproc=EventHub""", """Action: Allow""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\dZ)""",
    """"resourceId":"({resource_id}[^"]{1,2000})"""",
    """"msg":"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"operationName":"({activity}[^"]{1,2000})"""",
    """"msg":"[^"]{1,2000}?from\s({src_ip}[a-fA-F\d:\.]{1,2000}?)(:({src_port}\d{1,5}))?\s""",
    """"msg":"[^"]{1,2000}?to\s(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[^\s:"]{1,2000}))(:({dest_port}\d{1,5}))?\.\s""",
    """Action:\s({outcome}Allow)""",
    """"msg":"({protocol}[^\s]{1,2000})""",
    """requestClientApplication=({app}[^\s]{1,2000})""",
    """"({category}AzureFirewallApplicationRule)"""",
    """Rule:\s({rule}[^=]{1,2000}?)\s\w+=""",
    """Policy:\s({policy}[^\s]{1,2000}?)\.\s""",
    """\[Namespace:\s({event_hub_namespace}[^\s;\]]{1,2000})\s;\sEventHub name:\s({event_hub_name}[^\]]{1,2000})\]"""
  ]
  DupFields = [ "category->event_name", "outcome->action" ]


}
```