#### Parser Content
```Java
{
Name = mcafee-remote-logon
  Vendor = McAfee
  Product = McAfee Endpoint Security
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ATD""" , """"Action": "Successful user login"""" ]
  Fields = [
    """<\d+>\S+ \d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d ({host}\S+)""",
    """"Action":\s*"({event_code}[^"]+)""",
    """"User":\s*"({user}[^"]+)""",
    """"UserID":\s*"({user_id}[^"]+)""",
    """"Timestamp":\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Client":\s*"({src_ip}[a-fA-F\d.:]+)""",
    """"HTTPAgent":\s*"({user_agent}[^"]+)""",
  ]
}
```