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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvchost=({host}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuid=({account_used_id}.+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs1=({event_code}.+?)\s{1,100}(\w+=|$)""",
    """\Wdhost=({dest_host}.+?)\s{1,100}(\w+=|$)""",
    """\Wcs4=({logon_id}\d{1,100})""",
  ]
}
```