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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}bastion""",
    """({event_name}denied access)""",
    """bastion\d{0,100}:({hostname}[^:]{1,2000}):({user}[^:]{1,2000}):\s""",
    """:\s{1,100}({failure_reason}.+?)\s{0,100}$"""
  ]
}
```