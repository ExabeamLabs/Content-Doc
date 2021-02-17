#### Parser Content
```Java
{
Name = cef-ssh-login-failed
  Vendor = Unix
  Product = Unix
  Lms = Splunk
  DataType = "ssh-login"
  TimeFormat = "epoch"
  Conditions = [ """|Unix|Unix|""", """categoryOutcome=/Failure""", """cs1=ssh""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[^\s]+)""",
    """\Wdvchost=({host}[^\s]+)""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wshost=({src_host}[^\s]+)""",
    """\Wduser=({user}.+?)\s+\w+=""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdhost=({dest_host}[^\s]+)""",
    """\Wcs4=({logon_id}\d+)""",
    """CEF:([^\|]*\|){5}({failure_reason}[^\|]+)""",
    """({auth}password)""",
    """cs1=({event_code}.+?)\s+(\w+=|$)"""
  ]
}
```