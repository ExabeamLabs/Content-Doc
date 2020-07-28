#### Parser Content
```Java
{
Name = cef-carbonblack-workstation-locked
  Vendor = Carbon Black
  Product = Cb Protection
  Lms = ArcSight
  DataType = "workstation-locked"
  TimeFormat = "epoch"
  Conditions = [ """|Carbon Black|Protection|""", """Event[00000007] Type[SessionLock]""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[a-fA-F:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wdhost=(({domain}[^\\]+)\\+)?({dest_host}[^\\\s]+)""",
    """\Wdst=({dest_ip}[a-fA-F:\d.]+)""",
    """\Wduser=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)""",
    """\WEvent\[({event_code}\d+)\]\s*Type\[Session"""
  ]
}
```