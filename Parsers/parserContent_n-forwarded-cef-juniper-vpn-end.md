#### Parser Content
```Java
{
Name = n-forwarded-cef-juniper-vpn-end
  Vendor = Juniper Networks
  Lms = NitroCefSyslog
  DataType = "vpn-end"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", "|McAfee|", "SecureAccess", "User Session Ended" ]
  Fields = [
    """\srt=({time}\d+)""",
    """\sdeviceTranslatedAddress=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\ssuser=({user}.+?)\s*$""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
  ]
}
```