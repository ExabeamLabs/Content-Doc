#### Parser Content
```Java
{
Name = cef-moveit-app-failed-login
  Vendor = Ipswitch
  Product = IPswitch MoveIt
  Lms = Direct
  DataType = "failed-app-login"
  TimeFormat = "epoch"
  Conditions = [ """|IPswitch|MoveIt|""","""|FAILED: Sign On|""" ]
  Fields = [
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]{1,2000})\s\w+=""",
    """\srt=({time}\d{1,100})""",
    """\smsg=Failed to sign on:\s({failure_reason}.+?)\sart=""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]{1,2000})\s\w+=""",
    """requestClientApplication=({browser}.+?)\s\w+=""",
    """({app}MoveIt)"""
  ]


}
```