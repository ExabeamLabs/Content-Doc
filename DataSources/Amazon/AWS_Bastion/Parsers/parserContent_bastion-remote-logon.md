#### Parser Content
```Java
{
Name = bastion-remote-logon
  Vendor = Amazon
  Product = AWS Bastion
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """bastion:""", """logging onto""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}bastion:""",
    """({event_name}logging onto)""",
    """bastion:({hostname}[^:]{1,2000}):({user}[^:]{1,2000}):\s""",
    """([^,]{1,2000}
```