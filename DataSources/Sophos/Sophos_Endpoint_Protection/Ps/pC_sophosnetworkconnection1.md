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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"location":"({host}[\w\-.]{1,2000})"""",
    """Event::Endpoint::WindowsFirewall::({action}Blocked)""",
    """"when":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"name":"({additional_info}[^"]{1,2000})""""
    """"source_info":\s{0,100}\{[^\}]{0,2000}?"ip":\s{0,100}"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"type":"({event_name}[^"]{1,2000})"""",
    """"source":"({user}[^"]{1,2000})"""
    """"source":"(n\/a|(([^\\\s"]{0,2000}\s{1,100}[^\\"]{0,2000}|(DOMAIN|({domain}[^\\"]{1,2000})))\\+)?({user}[^\\\s"]{1,2000}))"""",
    
  ]
  DupFields = ["host->src_host","action->outcome"]
}
```