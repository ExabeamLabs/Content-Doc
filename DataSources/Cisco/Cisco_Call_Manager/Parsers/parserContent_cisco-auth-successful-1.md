#### Parser Content
```Java
{
Name = cisco-auth-successful-1
  Vendor = Cisco
  Product = Cisco Call Manager
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "MMM dd yyyy HH:mm:ss a"
  Conditions = [ """[Login Date/Time=""", """[Login IP Address/Hostname=""", """Login Authentication succeeded""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """Login Date/Time=({time}\d\d/\d\d/\d\d \d{1,100}:\d{1,100} (am|pm|AM|PM))""",
    """\s({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """Login IP Address/Hostname=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """Login UserID=({user}[^\]]{1,2000})""",
    """Node ID=({dest_host}[^\]]{1,2000})""",
    """Login Interface=({app}[^\]]{1,2000})""",
  ]
}
```