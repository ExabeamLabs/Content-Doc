#### Parser Content
```Java
{
Name = s-microsoft-print-activity-1
  Vendor = Microsoft
  Product = Windows PrintService
  Lms = Direct
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ was printed on """, """ Pages printed: """, """No user action is required.""", """ through port """, """ Size in bytes: """, """ owned by """ ]
  Fields = [
     """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
     """exabeam_host=({host}[\w.\-]{1,2000})""",
     """({activity}print)""",
     """Pages printed:\s{0,100}({num_pages}\d{1,100})""",
     """Size in bytes:\s{0,100}({bytes}\d{1,100})""",
     """,\s{1,100}({object}[^:]{1,2000}?)\s{1,100}owned by""",
     """printed on ({printer_name}[^\s]{1,2000})""",
     """owned by ({user}[^\s]{1,2000}) on ({src_host}[^\s]{1,2000})""",
     """through port (({dest_ip}[A-Fa-f:\d.]{1,2000})|({dest_host}[^\s]{1,2000}))(_\d{1,100})?\."""
  ]


}
```