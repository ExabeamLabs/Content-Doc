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
    """"Action":\s{0,100}"({event_code}[^"]{1,2000})""",
    """"User":\s{0,100}"({user}[^"]{1,2000})""",
    """"UserID":\s{0,100}"({user_id}[^"]{1,2000})""",
    """"Timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"Client":\s{0,100}"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"HTTPAgent":\s{0,100}"({user_agent}[^"]{1,2000})""",
  ]
}
```