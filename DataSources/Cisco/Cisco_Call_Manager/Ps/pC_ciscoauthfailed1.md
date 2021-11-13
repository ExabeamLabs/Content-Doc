#### Parser Content
```Java
{
Name = cisco-auth-failed-1
  Vendor = Cisco
  Product = Cisco Call Manager
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MMM dd yyyy HH:mm:ss a"
  Conditions = [ """AuthenticationFailed: """, """Login Authentication failed""", """App ID=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\s({time}\w+\s{1,100}\d{1,100}\s{1,100}\d{1,100}\s{1,100}\d{1,100}:\d{1,100}:\d{1,100}\s{1,100}(AM|PM|am|pm))""",
    """UserID\s{0,100}=({user}[^\s\]]{1,2000})""",
    """Login IP Address\/Hostname\s{0,100}=(({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}[\w\-.]{1,2000}))""",
    """\]:\s{0,100}({additional_info}.+?)\.?\s{1,100}$""",
    """App ID\s{0,100}=({app}[^\]]{1,2000})""",
  ]


}
```