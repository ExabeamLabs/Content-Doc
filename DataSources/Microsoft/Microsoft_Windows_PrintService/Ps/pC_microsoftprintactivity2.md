#### Parser Content
```Java
{
Name = microsoft-print-activity-2
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "MMM dd HH:mm:ss yyyy"
  Conditions = [ """Microsoft-Windows-PrintService""","""Printing a document""", """rn=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """owned by [^\s]{1,2000}\s{0,100}.*?( on [^\s]{1,2000})?({activity_2}.+?) on ({printer_name}.+?)(\.\s{1,100}|\s{1,100}through)""",
    """owned by ({user}.+?) (to|on) """,
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]{1,2000})|\\*({dest_host}.+?))\.\s{1,100}""",
    """Size in bytes:\s{1,100}({bytes}\d{1,100})""",
    """Pages printed:\s{1,100}({num_pages}\d{1,100})""",
    """[\[\(]{1,2000}({access}Read-Only)[\]\)]{1,2000}""",
    """({event_code}307)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """Document \d{1,100}
```