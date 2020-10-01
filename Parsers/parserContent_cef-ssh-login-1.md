#### Parser Content
```Java
{
Name = cef-ssh-login-1
  Vendor = Unix
  Product = Unix
  Lms = ArcSight
  DataType = "ssh-login"
  TimeFormat = "epoch"
  Conditions = [ """|session opened|""", """cs1=ssh""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvchost=({host}.+?)\s+(\w+=|$)""",
    """\Wsuid=({account_used_id}.+?)\s+(\w+=|$)""",
    """\Wduser=({user}.+?)\s+(\w+=|$)""",
    """\Wcs1=({event_code}.+?)\s+(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s+(\w+=|$)""",
    """\Wcs4=({logon_id}\d+)""",
  ]
}
```