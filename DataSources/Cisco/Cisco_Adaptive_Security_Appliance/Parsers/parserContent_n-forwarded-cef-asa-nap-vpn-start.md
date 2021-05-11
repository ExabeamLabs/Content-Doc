#### Parser Content
```Java
{
Name = n-forwarded-cef-asa-nap-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = NitroCefSyslog
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "Assigned private IP address", "|278-713228|" ]
    Fields = [
      """\srt=({time}\d{1,100})""",
      """\sshost=({host}[^\s]+)""",
      """\ssuser=({user}[^\r\n]+)\s{1,100}""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
  }
```