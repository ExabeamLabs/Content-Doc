#### Parser Content
```Java
{
Name = n-forwarded-cef-juniper-vpn-start
  Vendor = Juniper Networks
  Lms = NitroCefSyslog
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|McAfee|", "SecureAccess", "User Session Started" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sshost=({host}[^\s]+)""",
    """\ssuser=({user}.+?)\s*$""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```