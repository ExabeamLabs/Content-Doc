#### Parser Content
```Java
{
Name = cef-moveit-app-login
  Vendor = Ipswitch
  Product = IPswitch MoveIt
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "epoch"
  Conditions = [ """|IPswitch|MoveIt|""","""|Sign On|""" ]
  Fields = [
    """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sdvchost=({host}[^\s]+)\s\w+=""",
    """\srt=({time}\d{1,100})""",
    """\ssuser=({account_id}.+?)\s(\w+=|$)""",
    """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\sshost=({src_host}[^\s]+)\s\w+=""",
    """requestClientApplication=({browser}.+?)\s\w+=""",
    """({app}MoveIt)"""
  ]
   DupFields=["account_id->user"]
}
```