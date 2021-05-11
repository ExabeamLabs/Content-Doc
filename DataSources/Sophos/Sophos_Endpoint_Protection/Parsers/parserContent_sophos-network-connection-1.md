#### Parser Content
```Java
{
Name = sophos-network-connection-1
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::WindowsFirewall::Blocked"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[^\s]+)""",
    """"location":"({host}[\w\-.]+)"""",
    """Event::Endpoint::WindowsFirewall::({action}Blocked)""",
    """"when":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":"({additional_info}[^"]+)""""
    """"source_info":\s{0,100}\{[^\}]*?"ip":\s{0,100}"({src_ip}[A-Fa-f:\d.]+)""",
    """"type":"({event_name}[^"]+)"""",
    """"source":"({user}[^"]+)"""
    """"source":"(n\/a|(([^\\\s"]*\s{1,100}[^\\"]*|(DOMAIN|({domain}[^\\"]+)))\\+)?({user}[^\\\s"]+))"""",
    
  ]
  DupFields = ["host->src_host","action->outcome"]
}
```