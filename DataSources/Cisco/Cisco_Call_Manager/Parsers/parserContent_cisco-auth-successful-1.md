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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """Login Date/Time=({time}\d\d/\d\d/\d\d \d{1,100}:\d{1,100} (am|pm|AM|PM))""",
    """\s({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """Login IP Address/Hostname=({src_ip}[a-fA-F\d.:]+)""",
    """Login UserID=({user}[^\]]+)""",
    """Node ID=({dest_host}[^\]]+)""",
    """Login Interface=({app}[^\]]+)""",
  ]
}
```