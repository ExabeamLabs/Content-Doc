#### Parser Content
```Java
{
Name = pan-remote-logon
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ ",SYSTEM," , ",User" ,  " logged in " ]
  Fields = [
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """SYSTEM,.+?({time}\d\d\d\d\/\d\d\/\d\d \d\d:\d\d:\d\d)""",
    """User ({user}.+?) logged in .+?from (({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[^,]{1,2000}))""",
    """,SYSTEM,([^,]{0,2000}
```