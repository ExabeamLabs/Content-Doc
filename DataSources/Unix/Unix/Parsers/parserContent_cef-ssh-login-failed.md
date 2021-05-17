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
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[^\s]{1,2000})""",
    """\Wdvchost=({host}[^\s]{1,2000})""",
    """\Wsrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wshost=({src_host}[^\s]{1,2000})""",
    """\Wduser=({user}.+?)\s{1,100}\w+=""",
    """\Wdst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\Wdhost=({dest_host}[^\s]{1,2000})""",
    """\Wcs4=({logon_id}\d{1,100})""",
    """CEF:([^\|]{0,2000}\|){5}({failure_reason}[^\|]{1,2000})""",
    """({auth}password)""",
    """cs1=({event_code}.+?)\s{1,100}(\w+=|$)"""
  ]
}
```