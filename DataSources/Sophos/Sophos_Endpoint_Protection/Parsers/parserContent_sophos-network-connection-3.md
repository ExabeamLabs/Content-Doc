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
    """exabeam_host=([^=]+@\s*)?({host}[^\s]+)""",
    """"dhost":\s*"({src_host}[^"]+)""",
    """host="({host}[^"]+)""",
    """alert_id="({event_code}[^"]+)"""",
    """user="({user}[^"]+)""",
    """src_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """"dhost":\s*"({src_host}[^"]+)""",
    """rule_name="({rule}[^"]+)""",
    """alert_type="({event_name}[^"]+)"""",
    """rule_reason="({additional_info}[^"]+)\s*"""",
    """Event::Endpoint::WindowsFirewall::({action}Blocked)""",
  ]
  DupFields = [ "host->src_host","action->outcome" ]
}
```