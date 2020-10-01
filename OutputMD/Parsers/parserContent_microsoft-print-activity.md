#### Parser Content
```Java
{
Name = microsoft-print-activity
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """Microsoft-Windows-PrintService""","""Printing a document""" ]
  Fields = [
     """({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d (AM|PM|am|pm))""",
     """ComputerName=({host}[^\s]+)""",
     """Sid=({user_sid}[^\s]+)""",
     """OpCode=({outcome}.+?)\s+\w+=""",
     """EventCode=({event_code}\d+)""",
     """Message=({activity_1}.*?\s*(?i)Document) \d+,""",
     """owned by [^\s]+\s*.*?( on [^\s]+)?({activity_2}.+?) on ({printer_name}.+?)(\.\s+|\s+through)""",
     """Message=[^,]+,\s+({object}.+?) owned by""",
     """owned by ({user}.+?) (to|on) """,
     """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}.+?)) was """,
     """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]+)|\\*({dest_host}.+?))\.\s+""",
     """Size in bytes:\s+({bytes}\d+)""",
     """Pages printed:\s+({num_pages}\d+)""",
     """[\[\(]+({access}Read-Only)[\]\)]+"""
           ]
}
```