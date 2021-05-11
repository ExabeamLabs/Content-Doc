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
    """<\d{1,100}>\S+ \d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\+|\-)\d\d:\d\d ({host}\S+)""",
    """"Action":\s{0,100}"({event_code}[^"]+)""",
    """"User":\s{0,100}"({user}[^"]+)""",
    """"UserID":\s{0,100}"({user_id}[^"]+)""",
    """"Timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Client":\s{0,100}"({src_ip}[a-fA-F\d.:]+)""",
    """"HTTPAgent":\s{0,100}"({user_agent}[^"]+)""",
  ]
}
```