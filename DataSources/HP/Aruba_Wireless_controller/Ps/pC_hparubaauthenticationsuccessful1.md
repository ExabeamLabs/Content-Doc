#### Parser Content
```Java
{
Name = hp-aruba-authentication-successful-1
  Vendor = HP
  Product = Aruba Wireless controller
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """webui""", """ USER: """,""" has logged in from """ ]
  Fields = [
    """({time}\w{3}\s\d\d\s\d\d:\d\d\:\d\d\s\d\d\d\d)\s({host}[^\s]{1,2000})""",
    """USER:\s{0,100}({user}[^\s\@]{1,2000})""",
    """from\s({src_ip}[a-fA-F\d:\.]{1,2000}?)(\.?\s{0,100}$|\s\w+)""",
    """\s({event_name}logged in)""",
  ]


}
```