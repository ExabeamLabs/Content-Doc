#### Parser Content
```Java
{
Name = cef-juniper-failed-vpn-login
  Vendor = Juniper Networks
  Product = Juniper VPN
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ "CEF:", """|Pulse""", "|Login failed", "Reason:" ]
  Fields = [
   """\srt=({time}\d{1,100})""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})""",
    """\ssuser=(System|({user}.+?))\s{1,100}sproc=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Reason:\s{1,100}({failure_reason}.+?)(\|[^\s]{0,2000})?\s\w+=""" ]
}
}
```