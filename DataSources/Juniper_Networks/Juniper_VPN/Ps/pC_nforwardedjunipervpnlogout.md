#### Parser Content
```Java
{
Name = n-forwarded-juniper-vpn-logout
  Product = Juniper VPN
DataType = "vpn-end"
Conditions = [ "CEF:", "|McAfee|", "|SecureAccess", "User Logout|" ]

n-forwarded-juniper-vpn = {
  Vendor = Juniper Networks
  Lms = NitroCefSyslog
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\srt=({time}\d{1,100})""",
    """\sshost=({host}.+?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\ssuser=({user}[^\s@"]{1,2000})\s{1,100}(\w+=|$)""",
    """\ssuser=({user_email}[^\s@"]{1,2000}@[^\s@"]{1,2000})""",
    """\ssuser=({user_fullname}[^\s@"\=]{1,2000}\s{1,100}[^\s@"\=]{1,2000}?)(\s{1,100}\w+=|"{0,20}\s{0,100}$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdst=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdeviceTranslatedAddress=({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
  ]
  DupFields = ["user->account"
}
```