#### Parser Content
```Java
{
Name = openvpn-failed-vpn-login
  Vendor = SSL Open VPN
  Product = SSL Open VPN
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  Conditions = [ """] VPN Auth Failed: """ ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\+|\-)\d+).*?VPN Auth Failed:""",
    """VPN Auth Failed:\s*'({failure_reason}[^']+)""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[({user}[^\s\]]+)\] Peer Connection Initiated with""",
  ]
}
```