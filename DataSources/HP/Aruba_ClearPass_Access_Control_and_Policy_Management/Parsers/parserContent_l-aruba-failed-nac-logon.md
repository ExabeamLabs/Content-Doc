#### Parser Content
```Java
{
Name = l-aruba-failed-nac-logon
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = Direct
  DataType = "nac-failed-logon"
  TimeFormat = "yyyy-mm-dd'T'HH:mm:ss"
  Conditions = [ """Authentication failed""", """method=""", """server=""", """authmgr""" ]
  Fields = [
      """({time}\d{4}-\d{2}-\d{2}T\d\d:\d\d:\d\d)\+""",
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}\s({dest_ip}[.:a-fA-F\d]+)""",
      """\s+({host}[^\s]+)\s+authmgr\[""",
      """(authmgr|stm)\[({event_code}\d+)\]""",
      """Authentication result=({event_name}Authentication failed)""",
      """method=({auth_type}[^\,\s]+)""",
      """server=({auth_server}[\w\d]+)""",
      """user=({src_mac}[a-fA-F\d:]+)""",
   ]
}
```