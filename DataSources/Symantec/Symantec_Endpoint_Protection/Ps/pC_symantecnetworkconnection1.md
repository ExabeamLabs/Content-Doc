#### Parser Content
```Java
{
Name = symantec-network-connection-1
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """,User Name: """, """,Action: """, """,Domain Name: """, """,Rule: """, """,Location: """ ]
  Fields = [
    """({direction}Inbound|Outbound),Begin:\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\+\d{1,100}:\d{1,100}
```