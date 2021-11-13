#### Parser Content
```Java
{
Name = cef-carbonblack-workstation-locked
  Vendor = VMware
  Product = App Control
  Lms = ArcSight
  DataType = "workstation-locked"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", """Event[00000007] Type[SessionLock]""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[a-fA-F:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """\Wdhost=(({domain}[^\\]{1,2000})\\+)?({dest_host}[^\\\s]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """\Wduser=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
    """\WEvent\[({event_code}\d{1,100})\]\s{0,100}Type\[Session"""
  ]


}
```