#### Parser Content
```Java
{
Name = raw-juniper-failed-vpn-login
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = Direct
  DataType = "failed-vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Login failed using auth server", "Reason:" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\stime="({time}[^"]+)"""",
    """\w+\s*\d+\s*\d\d:\d\d:\d\d\s*({host}[\w\-\.]+)\s*:\s*\(""",
    """\svpn=({host}[\w\-\.]+)\s""",
    """\d\d:\d\d:\d\d\s+-\s+\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@]+@[^@(]+)|({user}.+?))\(""",
    """Reason:\s+({failure_reason}[^"]+?)\s*("|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """user=(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}.+?))\s+\w+=""",
    """\s+({host}[\w\-.]+)\s+\S+\s+PulseSecure:""",
    """PulseSecure:\s*({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s+\-\s+({host}[\w\-.]+)""",
    """PulseSecure:.*?\[({src_ip}[a-fA-F:\d.]+)\]\s+(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}[^\s]+))\(({realm}[^\[]+)?\)\[([^\-]*)\-\s*({failure_reason}[^\-\.]+)?\s*""",
  ]
  DupFields = [ "host->dest_host" ]
}
```