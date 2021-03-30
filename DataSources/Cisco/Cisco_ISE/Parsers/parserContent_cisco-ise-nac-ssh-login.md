#### Parser Content
```Java
{
Name = cisco-ise-nac-ssh-login
  Vendor = Cisco
  Product = Cisco ISE
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """A SSH CLI user has successfully logged in""", """|Cisco|Cisco ISE|""", """CEF:""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """dvchost=({host}[^\s]+)""",
    """({event_name}A SSH CLI user has successfully logged in)""",
    """Cisco ISE\|*({event_code}\d+)\|""",
    """destinationServiceName=({app}[^\s]+)""",
    """cat=({category}[^\s]+)\s""",
    """deviceSeverity=({severity}[^\s]+)""",
    """({outcome}Success)""",
    """ad.User=({user}[^\s]+)""",
    """suser=({user}[^\s]+)""",
  ]
}
```