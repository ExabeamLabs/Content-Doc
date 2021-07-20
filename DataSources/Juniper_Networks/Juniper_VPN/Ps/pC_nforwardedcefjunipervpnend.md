#### Parser Content
```Java
{
Name = n-forwarded-cef-juniper-vpn-end
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = NitroCefSyslog
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|McAfee|", "SecureAccess", "User Session Ended" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}.+?)\s{0,100}$""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```