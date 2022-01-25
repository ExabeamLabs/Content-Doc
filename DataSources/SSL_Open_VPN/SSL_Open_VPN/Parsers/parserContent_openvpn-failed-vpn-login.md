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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\+|\-)\d{1,100}).*?VPN Auth Failed:""",
    """VPN Auth Failed:\s{0,100}'({failure_reason}[^']{1,2000})""",
    """({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[({user}[^\s\]]{1,2000})\] Peer Connection Initiated with""",
  ]
}
```