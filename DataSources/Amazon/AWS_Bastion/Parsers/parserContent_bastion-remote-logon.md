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
    """\d\d:\d\d:\d\d\s+({host}[^\s]+)\s+bastion:""",
    """({event_name}logging onto)""",
    """bastion:({hostname}[^:]+):({user}[^:]+):\s""",
    """([^,]+,){2}\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""" 
  ]
}
```