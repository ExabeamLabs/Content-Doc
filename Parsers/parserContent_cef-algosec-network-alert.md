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
   """exabeam_host=([^=]+@\s*)?({host}\S+)""",
   """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
   """({host}[^\s]+)\s+:\s+CEF""",
   """CEF:\d+\|([^\|]+\|){2}({version}[^\|]+)""",
   """CEF:\d+\|([^\|]+\|){3}({alert_type}[^\|]+)""",
   """({alert_name}Unauthorized traffic)""",
   """msg=Summary:\s+\w+\s*({alert_severity}\d+)""",
   """Unauthorized traffic from\s+({src_network}.+?)\s+to\s+({dest_network}[^\s]+)\s+""",
     ]
}
```