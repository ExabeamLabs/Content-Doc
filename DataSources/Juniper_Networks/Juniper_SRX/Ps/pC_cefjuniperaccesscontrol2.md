#### Parser Content
```Java
{
Name = cef-juniper-access-control-2
  DataType = "access-control"
  Conditions = [ """CEF:""", """|McAfee|ESM|""", """|SecureAccess_v7 Added user to authentication server|""" ]

cef-juniper-vpn-events = {
  Vendor = Juniper Networks
  Product = Juniper SRX
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """\s({host}[\w\-.]{1,2000})\s{1,100}CEF:""",
    """\Wrt=({time}\d{1,100})""",
    """\WdeviceTranslatedAddress=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wdst=({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wsuser=({user}[^\s@]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^\s@]{1,2000}@[^\s@]{1,2000})""",
    """\Wact=({outcome}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = ["user->account"
}
```