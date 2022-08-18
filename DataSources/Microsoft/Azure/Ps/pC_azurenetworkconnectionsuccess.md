#### Parser Content
```Java
{
Name = azure-network-connection-success
  Vendor = Microsoft
  Product = Azure
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """destinationServiceName =Azure""", """"category":"AzureFirewallNetworkRule"""", """"resourceId":"""", """dproc=EventHub""", """Action: Allow""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d\dZ)""",
    """"resourceId":"({resource_id}[^"]{1,2000})"""",
    """"msg":"({additional_info}[^"]{1,2000}?)\s{0,100}"""",
    """"msg":"({protocol}\S{1,2000}?) request from ({src_ip}[A-Fa-f\d.:]{1,2000}?):({src_port}\d{1,5}?) to ({dest_ip}[A-Fa-f\d.:]{1,2000}?):({dest_port}\d{1,5})""",
    """"operationName":"({activity}[^"]{1,2000})"""",
    """"category":"({category}AzureFirewallNetworkRule)""",
    """Action: ({outcome}Allow)""",
    """requestClientApplication=({app}[^=]{1,2000}?)\s{1,100}\w+?=""",
    """Namespace:\s{0,100}({event_hub_namespace}[^]]{1,2000}?)\s{0,100};\s{0,100}EventHub name:\s{0,100}({event_hub_name}[^]]{1,2000}?)\]\s{0,100}"""
   ]


}
```