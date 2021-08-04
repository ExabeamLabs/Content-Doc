#### Parser Content
```Java
{
Name = s-phantom-dlp-email-in
  Vendor = Phantom
  Product = Phantom
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """from: """, """,to: """, """,subject: """, """,analysed_time: """, """phantom""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """,analysed_time:\s{0,100}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """from:\s{0,100}({sender}[^\s@,]{1,2000}@[^\s@,]{1,2000})""",
    """,to:\s{0,100}({recipients}({recipient}[^\s@,;]{1,2000}@({external_domain}[^\s@,;]{1,2000}))[^,]{0,2000}?)\s{0,100}
```