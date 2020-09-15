#### Parser Content
```Java
{
Name = microsoft-print-activity-1
  Vendor = Microsoft
  Product = Microsoft Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """Microsoft-Windows-PrintService""", """Printing a document""", """<EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
    """<Computer>({host}[\w\-.]+)""",
    """UserID='({user_sid}[^\s']+)""",
    """<Opcode>({outcome}[^\d<]+)""",
    """<EventID>({event_code}\d+)""",
    """<Message>({activity_1}.*?\s*(?i)Document) \d+,""",
    """owned by [^\s]+\s*.*?( on [^\s]+)?({activity_2}.+?) on ({printer_name}.+?)(\.\s+|\s+through)""",
    """<Message>[^,]+,\s+({object}.+?)\s+owned by""",
    """owned by ({user}.+?) (to|on) """,
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]+)|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]+)|\\*({dest_host}.+?))\.\s+""",
    """Size in bytes:\s+({bytes}\d+)""",
    """Pages printed:\s+({num_pages}\d+)""",
    """({access}Read-Only)""",
  ]
  DupFields = [ "object->file_name" ]
}
```