#### Parser Content
```Java
{
Name = microsoft-dns-update-successful
   Vendor = Microsoft
   Product = Microsoft Windows
   Lms = Splunk
   DataType = "dhcp"
   TimeFormat = "MM/dd/yy,HH:mm:ss"
   Conditions = [  """,DNS Update Successful,""" ]
   Fields = [
      """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s({src_host}\S+)\s[^,\s]+,""",
      """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d)""",
      """({event_name}DNS Update Successful)""",
      """DNS Update Successful,({dest_ip}[A-Fa-f:\d.]+)""",
      """DNS Update Successful,(([^,]+),){1}({dest_host}[^,]+)""",
      """<leaf>\S+\s{1,100}({host}[^\s<]+)\s{1,100}({src_ip}[A-Fa-f:\d.]+)"""
   ]
  DupFields = [ "dest_host->user" ]
}
```