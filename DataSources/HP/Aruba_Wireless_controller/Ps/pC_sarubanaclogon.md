#### Parser Content
```Java
{
Name = s-aruba-nac-logon
  Vendor = HP
  Product = Aruba Wireless controller
  Lms = Splunk
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """,attr_name=Connection:Src-IP-Address,""", """,attr_value=""" ]
  Fields = [
    """({host}[A-Fa-f:\d.]{1,2000})\s({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),\d{1,100}\s({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """,session_id=({session_id}[^,]{1,2000})""",
    """,type=({auth_type}[^,]{1,2000})""",
    """,attr_name=Connection:Src-IP-Address,attr_value=({src_ip}[A-Fa-f:\d.]{1,2000})""",
  ]
  DupFields = [ "host->auth_server" ]
}
}
```