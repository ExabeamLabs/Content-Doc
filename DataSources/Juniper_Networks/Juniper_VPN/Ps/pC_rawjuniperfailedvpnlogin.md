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
    """\stime="({time}[^"]{1,2000})"""",
    """\w+\s{0,100}\d{1,100}\s{0,100}\d\d:\d\d:\d\d\s{0,100}({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-\.]{1,2000})))\s{0,100}:\s{0,100}\(""",
    """\svpn=({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-\.]{1,2000})))\s""",
    """exabeam_host=({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-.]{1,2000})))""",
    """\s{1,100}({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-.]{1,2000})))\s{1,100}PulseSecure:""",
    """\d\d:\d\d:\d\d\s{1,100}-\s{1,100}\[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@]{1,2000}@[^@(]{1,2000})|({user}.+?))\(""",
    """Reason:\s{1,100}({failure_reason}[^"]{1,2000}?)\s{0,100}("|$)""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """user=(({domain}[^\\]{1,2000})\\)?(?:({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})|({user}.+?))\s{1,100}\w+=""",
    """\s{1,100}({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-.]{1,2000})))\s{1,100}\S+\s{1,100}PulseSecure:""",
    """PulseSecure:\s{0,100}({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)\s{1,100}\-\s{1,100}({host}(({dest_ip}(\d{1,3}\.){3}\d{1,3})|({dest_host}[\w\-.]{1,2000})))""",
    """PulseSecure:[^\[]{1,2000}\[({src_ip}[A-Fa-f.\d:]{1,2000})\]\s{1,100}([\w\s]{1,2000}?::)?(({domain}[^\s\\]{1,2000})\\+)?(\?|(?:({user_email}[^@\s]{1,2000}@[^@\s\(]{1,2000})|({user}[^\\\s\(]{1,2000})))\(({realm}[^\[]{1,2000})?\)\[([^\-]{0,2000})\-\s{0,100}({failure_reason}[^\-\.]{1,2000})?\s{0,100}"""
  ]


}
```