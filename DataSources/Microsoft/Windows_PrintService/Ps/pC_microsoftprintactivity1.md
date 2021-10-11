#### Parser Content
```Java
{
Name = microsoft-print-activity-1
  Vendor = Microsoft
  Product = Windows PrintService
  Lms = Splunk
  DataType = "print-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """Microsoft-Windows-PrintService""", """Printing a document""", """<EventID>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """<Computer>({host}[\w\-.]{1,2000})""",
    """UserID='({user_sid}[^\s']{1,2000})""",
    """<Opcode>({outcome}[^\d<]{1,2000})""",
    """<EventID>({event_code}\d{1,100})""",
    """<Message>({activity_1}.*?\s{0,100}(?i)Document) \d{1,100},""",
    """owned by [^\s]{1,2000}\s{0,100}.*?( on [^\s]{1,2000})?({activity_2}.+?) on ({printer_name}.+?)(\.\s{1,100}|\s{1,100}through)""",
    """<Message>[^,]{1,2000},\s{1,100}({object}.+?)\s{1,100}owned by""",
    """owned by ({user}.+?) (to|on) """,
    """owned by.+? on \\*(?:({src_ip}[A-Fa-f:\d.]{1,2000})|({src_host}.+?)) was """,
    """through port (\w+_)?(?:({dest_ip}[A-Fa-f:\d.]{1,2000})|\\*({dest_host}.+?))\.\s{1,100}""",
    """Size in bytes:\s{1,100}({bytes}\d{1,100})""",
    """Pages printed:\s{1,100}({num_pages}\d{1,100})""",
    """({access}Read-Only)""",
  ]
  DupFields = [ "object->file_name" ]
}
```