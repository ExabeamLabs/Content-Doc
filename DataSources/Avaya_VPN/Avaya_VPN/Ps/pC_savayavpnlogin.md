#### Parser Content
```Java
{
Name = s-avaya-vpn-login
    Vendor = Avaya VPN
  Product = Avaya VPN
    Lms = Splunk
    DataType = "vpn-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """ LoginSucceeded """, """avaya:vpn""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s{1,100}({host}[\w.\-]{1,2000})\s{1,100}SSL:""",
      """\sSrcIp="({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\sUser="(({domain}[^\\"]{1,2000})\\+)?({user}[^"]{1,2000})""",
      """\sGroups="({realm}[^"]{1,2000}?)\/?\s{0,100}"""",
      """\sTunIP="({dest_ip}[a-fA-F\d.:]{1,2000})""",
    ]
  }
```