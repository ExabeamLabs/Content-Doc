#### Parser Content
```Java
{
Name = n-forwarded-cef-asa-svc-vpn-start
    Vendor = Cisco
    Product = Cisco Adaptive Security Appliance
    Lms = NitroCefSyslog
    DataType = "vpn-start"
    TimeFormat = "epoch"
    Conditions = [ "Address assigned to session", "|278-722051|" ]
    Fields = [ """\srt=({time}\d{1,100})""",
      """\sshost=({host}[^\s]+)""",
      """\ssuser=({user}.+?)\snitroGroup_Name=""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
  }
```