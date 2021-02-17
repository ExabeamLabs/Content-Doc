#### Parser Content
```Java
{
Name = s-avaya-failed-vpn-login
    Vendor = Avaya VPN
    Lms = Splunk
    DataType = "failed-vpn-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """ LoginFailed """, """avaya:vpn""" ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d)\s+({host}[\w.\-]+)\s+SSL:""",
      """\sSrcIp="({src_ip}[a-fA-F\d.:]+)""",
      """\sUser="(({domain}[^\\"]+)\\+)?({user}[^"]+)""",
      """\sError="({failure_reason}[^"]+)""",
    ]
  }
```