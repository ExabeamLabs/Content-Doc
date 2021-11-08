#### Parser Content
```Java
{
Name = s-aruba-nac-logon-1
  Vendor = HP
  Product = Aruba Wireless controller
  Lms = Splunk
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,attr_name=Authentication:Full-Username,""", """,attr_value=""" ]
  Fields = [
    """({host}[A-Fa-f:\d.]{1,2000})\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),\d{1,100}\s({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """,session_id=({session_id}[^,]{1,2000})""",
    """,type=({auth_type}[^,]{1,2000})""",
    """,attr_name=Authentication:Full-Username,attr_value=({user}[^,\s@\\\/]{1,2000}),""",
    """,attr_name=Authentication:Full-Username,attr_value=({user_fullname}[^,\s@]{1,2000})@({domain}[^,@]{1,2000})""",
    """,attr_name=Authentication:Full-Username,attr_value=(host/|(({domain}[^,\\\/]{1,2000})[\\\/]{1,2000})({user_fullname}[^,\s@]{1,2000}))""",
  ]
  DupFields = [ "host->auth_server" ]
}
```