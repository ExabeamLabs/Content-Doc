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
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}bastion:""",
    """({event_name}logging onto)""",
    """bastion:({hostname}[^:]+):({user}[^:]+):\s""",
    """([^,]+,){2}\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""" 
  ]
}
```