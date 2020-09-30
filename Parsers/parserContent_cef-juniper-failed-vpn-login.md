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
   """\srt=({time}\d+)""",
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)""",
    """\ssuser=(System|({user}.+?))\s+sproc=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """Reason:\s+({failure_reason}.+?)(\|[^\s]*)?\s\w+=""" ]
}
```