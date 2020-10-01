#### Parser Content
```Java
{
Name = netscaler-cef-failed-vpn-login
  Vendor = Citrix
  Product = Citrix Netscaler
  Lms = ArcSight
  DataType = "failed-vpn-login"
  TimeFormat = "epoch"
  Conditions = [ """|Citrix|NetScaler|""", """|LOGIN_FAILED|""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[a-fA-F:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]+)""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wsuser=({user}\S+)""",
    """\Wreason=({failure_reason}.+?)\s*(\w+=|$)""",
  ]
}
```