#### Parser Content
```Java
{
Name = cisco-tacacs-authentication-failed
  Vendor = Cisco
  Product = TACACS
  Lms = Direct
  DataType = "authentication-failed"
  TimeFormat = "MMM dd yyyy HH:mm:ss.SSS z"
  Conditions = [ """Component=TacacsServer""", """Action=Failed""", """Authorization request""" ]
  Fields = [
    """Timestamp=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d\.\d\d\d\s\w{3})""",
    """,\d{1,3}\s({host}[\w\-.]{1,2000})\s""",
    """Action=({outcome}[^,]{1,2000})""",
    """Description=({event_name}[^=]{1,2000})\s\w+=""",
    """user=({user}[^\s;]{1,2000})"""
  ]


}
```