#### Parser Content
```Java
{
Name = s-avaya-vpn-login
    Vendor = Avaya VPN
    Lms = Splunk
    DataType = "vpn-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """ LoginSucceeded """, """avaya:vpn""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}[\w.\-]+)\s+SSL:""",
      """\sSrcIp="({src_ip}[a-fA-F\d.:]+)""",
      """\sUser="(({domain}[^\\"]+)\\+)?({user}[^"]+)""",
      """\sGroups="({realm}[^"]+?)\/?\s*"""",
      """\sTunIP="({dest_ip}[a-fA-F\d.:]+)""",
    ]
  }
```