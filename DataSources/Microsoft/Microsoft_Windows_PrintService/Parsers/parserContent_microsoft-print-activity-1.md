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
    """<TimeCreated SystemTime='({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """<Computer>({host}[\w\-.]+)""",
    """UserID='({user_sid}[^\s']+)""",
    """<Opcode>({outcome}[^\d<]+)""",
    """<EventID>({event_code}\d{1,100})""",
    """<Message>({activity_1}.*?\s{0,100}(?i)Document) \d{1,100}
```