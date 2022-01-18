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
     """ComputerName =({host}[^\s]{1,2000})""",
     """Sid=({user_sid}[^\s]{1,2000})""",
     """OpCode=({outcome}.+?)\s{1,100}\w+=""",
     """EventCode=({event_code}\d{1,100})""",
     """Message=({activity_1}.*?\s{0,100}(?i)Document) \d{1,100

}
```