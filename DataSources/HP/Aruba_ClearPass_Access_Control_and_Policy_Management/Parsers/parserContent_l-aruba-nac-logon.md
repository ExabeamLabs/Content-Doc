#### Parser Content
```Java
{
Name = l-aruba-nac-logon
   Vendor = HP
   Product = Aruba ClearPass Access Control and Policy Management
   Lms = Direct
   DataType = "nac-logon"
   TimeFormat = "yyyy-mm-dd'T'HH:mm:ss"
   Conditions = ["""Authentication Successful""", """method=""", """server=""", """authmgr"""]
   Fields = [
      """({time}\d{4}-\d{2}-\d{2}T\d\d:\d\d:\d\d)\+""",
      """\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{2}:\d{2}\s({dest_ip}[.:a-fA-F\d]+)""",
      """\s{1,100}({host}[^\s]+)\s{1,100}authmgr\[""",
      """(authmgr|stm)\[({event_code}\d{1,100})\]""",
      """username=(({domain}[^\\\s\@]+)\\|({user_type}host)\/)?({user_email}[^\s\@]+\@({email_domain}[^\s]+))?({src_mac}([0-9a-fA-F]{1,2}[.:-]){5}([0-9a-fA-F]{1,2}))?({user}[^\s]+)?""",
      """MAC=({src_mac}[a-fA-F\d:]+)""",
      """user=({src_mac}[a-fA-F\d:]+)""",
      """Authentication result=({event_name}Authentication Successful)""",
      """method=({auth_type}[^\,\s]+)""",
      """server=({auth_server}[\w\d]+)""",
   ]
}
```