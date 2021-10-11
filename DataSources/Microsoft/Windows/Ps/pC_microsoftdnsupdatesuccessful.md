#### Parser Content
```Java
{
Name = microsoft-dns-update-successful
   Vendor = Microsoft
   Product = Windows
   Lms = Splunk
   DataType = "dhcp"
   TimeFormat = "MM/dd/yy,HH:mm:ss"
   Conditions = [  """,DNS Update Successful,""" ]
   Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s({src_host}\S+)\s[^,\s]{1,2000},""",
      """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
      """({event_name}DNS Update Successful)""",
      """DNS Update Successful,({dest_ip}[A-Fa-f:\d.]{1,2000})""",
      """DNS Update Successful,(([^,]{1,2000}),){1}({dest_host}[^,]{1,2000})""",
      """<leaf>\S+\s{1,100}({host}[^\s<]{1,2000})\s{1,100}({src_ip}[A-Fa-f:\d.]{1,2000})"""
   ]
  DupFields = [ "dest_host->user" ]
}
```