#### Parser Content
```Java
{
Name = cef-unix-account-switch
  Vendor = Unix
  Product = Unix
  Lms = ArcSight
  DataType = "unix-account-switch"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """|session opened|""", """cs1=runuser""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvchost=({host}.+?)\s+(\w+=|$)""",
    """\Wsuid=({user_uid}.+?)\s+(\w+=|$)""",
    """\Wduser=({account}.+?)\s+(\w+=|$)""",
    """\Wcs1=({process_name}.+?)\s+(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "process_name->event_code" ]
}
```