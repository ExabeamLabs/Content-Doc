#### Parser Content
```Java
{
Name = n-forwarded-cef-asa-nap-vpn-end
    Vendor = Cisco
    Product = Adaptive Security Appliance
    Lms = NitroCefSyslog
    DataType = "vpn-end"
    TimeFormat = "epoch"
    Conditions = [ "Session is being torn down", "|278-713259|" ]
    Fields = [ """\srt=({time}\d{1,100})""",
      """\sshost=({host}[^\s]{1,2000})""",
      """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
      """\ssuser=({user}[^\r\n]{1,2000})\s{1,100}"""
    ]
  

}
```