#### Parser Content
```Java
{
Name = n-forwarded-cef-juniper-vpn-start
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = NitroCefSyslog
  DataType = "vpn-start"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|McAfee|", "SecureAccess", "User Session Started" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sshost=({host}[^\s]{1,2000})""",
    """\ssuser=({user}.+?)\s{0,100}$""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```