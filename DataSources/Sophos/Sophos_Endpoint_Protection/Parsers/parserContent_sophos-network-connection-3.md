#### Parser Content
```Java
{
Name = sophos-network-connection-3
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Event::Endpoint::WindowsFirewall::Blocked"""" ]
  Fields = [
    """\s({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"dhost":\s{0,100}"({src_host}[^"]{1,2000})""",
    """host="({host}[^"]{1,2000})""",
    """alert_id="({event_code}[^"]{1,2000})"""",
    """user="({user}[^"]{1,2000})""",
    """src_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"dhost":\s{0,100}"({src_host}[^"]{1,2000})""",
    """rule_name="({rule}[^"]{1,2000})""",
    """alert_type="({event_name}[^"]{1,2000})"""",
    """rule_reason="({additional_info}[^"]{1,2000})\s{0,100}"""",
    """Event::Endpoint::WindowsFirewall::({action}Blocked)""",
  ]
  DupFields = [ "host->src_host","action->outcome" ]
}
```