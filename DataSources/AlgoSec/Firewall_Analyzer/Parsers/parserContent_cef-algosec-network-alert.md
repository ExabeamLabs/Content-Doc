#### Parser Content
```Java
{
Name = cef-algosec-network-alert
 Product = Firewall Analyzer
 Vendor = AlgoSec
 Lms = Direct
 DataType = "network-alert"
 TimeFormat ="yyyy-MM-dd HH:mm:ss"
 Conditions = [ """CEF:""", """|AlgoSec|Firewall Analyzer|""", """Unauthorized traffic""" ]
 Fields =[
   """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """({host}[^\s]+)\s{1,100}:\s{1,100}CEF""",
   """CEF:\d{1,100}\|([^\|]+\|){2}({version}[^\|]+)""",
   """CEF:\d{1,100}\|([^\|]+\|){3}({alert_type}[^\|]+)""",
   """({alert_name}Unauthorized traffic)""",
   """msg=Summary:\s{1,100}\w+\s{0,100}({alert_severity}\d{1,100})""",
   """Unauthorized traffic from\s{1,100}({src_network}.+?)\s{1,100}to\s{1,100}({dest_network}[^\s]+)\s{1,100}""",
     ]
}
```