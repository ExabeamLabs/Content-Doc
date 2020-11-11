#### Parser Content
```Java
{
Name = n-forwarded-cef-asa-svc-vpn-end
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = NitroCefSyslog
    DataType = "vpn-end"
    TimeFormat = "epoch"
    Conditions = [ "Session disconnected", "|278-113019|" ]
    Fields = [ """\srt=({time}\d+)""",
      """\sshost=({host}[^\s]+)""",
      """\ssuser=({user}[^\r\n]+)\s+""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
  }
```