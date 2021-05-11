#### Parser Content
```Java
{
Name = s-avaya-failed-vpn-login
    Vendor = Avaya VPN
  Product = Avaya VPN
    Lms = Splunk
    DataType = "failed-vpn-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """ LoginFailed """, """avaya:vpn""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s{1,100}({host}[\w.\-]+)\s{1,100}SSL:""",
      """\sSrcIp="({src_ip}[a-fA-F\d.:]+)""",
      """\sUser="(({domain}[^\\"]+)\\+)?({user}[^"]+)""",
      """\sError="({failure_reason}[^"]+)""",
    ]
  }
```