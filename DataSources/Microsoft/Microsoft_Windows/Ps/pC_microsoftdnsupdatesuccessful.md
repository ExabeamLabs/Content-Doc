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
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """\d\d:\d\d:\d\d\s({src_host}\S+)\s[^,\s]{1,2000}
```