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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Wsrc=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    """\Wsuser=({user}\S+)""",
    """\Wreason=({failure_reason}.+?)\s{0,100}(\w+=|$)""",
  ]
}
```