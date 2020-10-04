#### Parser Content
```Java
{
Name = openvpn-auth-failed-2
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """AUTH_FAILED""", """openvpn"""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d+)""",
    """(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d+\s\d+:\d+:\d+\s\d+.*?({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d+).*?\[({user}[^\]]+)""",
    """SESSION:({additional_info}[^']+)""",
    """status=({outcome}\d+)"""
  ]
}
```