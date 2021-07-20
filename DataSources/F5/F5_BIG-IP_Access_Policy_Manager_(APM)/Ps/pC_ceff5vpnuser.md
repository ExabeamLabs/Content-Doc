#### Parser Content
```Java
{
Name = cef-f5-vpn-user
  Vendor = F5
  Product = F5 BIG-IP Access Policy Manager (APM)
  Lms = ArcSight
  DataType = "vpn-user"
  TimeFormat = "epoch"
  Conditions = [ """|F5|APM|""", """Username|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sduser=({user}.+?)(?:\s{1,100}[\w.]{1,2000}=|\s{0,100}$)""",
    """\scs4=({session_id}.+?)(?:\s{1,100}[\w.]{1,2000}=|\s{0,100}$)""",
    """\sdvc=({host}[a-fA-F\d.:]{1,2000})""",
    """\sdvchost=({host}.+?)(?:\s{1,100}[\w.]{1,2000}=|\s{0,100}$)"""
  ]
}
```