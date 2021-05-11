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
    """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\stime="({time}[^"]+)"""",
    """\w+\s{0,100}\d{1,100}\s{0,100}\d\d:\d\d:\d\d\s{0,100}({host}[\w\-\.]+)\s{0,100}:\s{0,100}\(""",
    """\svpn=({host}[\w\-\.]+)\s""",
    """exabeam_host=({host}[\w.\-]+)""",
    """\s{1,100}({host}[\w-.]+)\s{1,100}PulseSecure:""",
    """\d\d:\d\d:\d\d\s{1,100}-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]+)\\)?(?:({user_email}[^@]+@[^@(]+)|({user}.+?))\(""",
    """Reason:\s{1,100}({failure_reason}[^"]+?)\s{0,100}("|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """user=(({domain}[^\\]+)\\)?(?:({user_email}[^@\s]+@[^@\s]+)|({user}.+?))\s{1,100}\w+=""",
    """\s{1,100}({host}[\w\-.]+)\s{1,100}\S+\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}[\w\-.]+)""",
    """PulseSecure:[^\[]+\[({src_ip}[A-Fa-f.\d:]+)\]\s{1,100}([\w\s]+?::)?(({domain}[^\s\\]+)\\+)?(\?|(?:({user_email}[^@\s]+@[^@\s\(]+)|({user}[^\\\s\(]+)))\(({realm}[^\[]+)?\)\[([^\-]*)\-\s{0,100}({failure_reason}[^\-\.]+)?\s{0,100}"""
  ]
  DupFields = [ "host->dest_host" ]
}
```