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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d{1,100})""",
    """(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s\d{1,100}\s\d{1,100}:\d{1,100}:\d{1,100}\s\d{1,100}.*?({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}):({src_port}\d{1,100}).*?\[({user}[^\]]{1,2000})""",
    """SESSION:({additional_info}[^']{1,2000})""",
    """status=({outcome}\d{1,100})"""
  ]
}
```