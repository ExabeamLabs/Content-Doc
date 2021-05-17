#### Parser Content
```Java
{
Name = cef-unix-su
  Vendor = Unix
  Product = Unix
  Lms = ArcSight
  DataType = "unix-account-switch"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """|session opened|""", """cs1=su """ ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sduser=({user}.+?)\s{1,100}\w+=""",
    """\sdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdhost=({dest_host}[^\s]{1,2000})""",
    """session opened for user ({account}.+?) by""",
    """session opened for user.+?by ({user}[^(]{1,2000})""",
    """\(uid\\+=({user_uid}\d{1,100})\)""",
    """({event_code}su)"""
  ]
  DupFields = [ "dest_host->host"]
}
```