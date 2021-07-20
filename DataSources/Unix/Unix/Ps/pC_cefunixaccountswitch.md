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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuid=({user_uid}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({account}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=({process_name}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "process_name->event_code" ]
}
```