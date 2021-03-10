#### Parser Content
```Java
{
Name = bastion-failed-logon
  Vendor = Amazon
  Product = AWS Bastion
  Lms = Splunk
  DataType = "failed-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ bastion""", """denied access""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+bastion""",
    """({event_name}denied access)""",
    """bastion\d*:({hostname}[^:]+):({user}[^:]+):\s""",
    """:\s+({failure_reason}.+?)\s*$"""
  ]
}
```