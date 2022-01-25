#### Parser Content
```Java
{
Name = code42-email-out-operations
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss:SSZ"
  Conditions= [ """"fileCategoryByExtension"""",  """"eventType":"EMAILED"""", """"osHostName""", """act=send""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """"eventType"{1,20}:\s{0,100}"{1,20}({event_code}[^"]{1,2000})""",
    """"source":"{1,20}({log_source}[^"]{1,2000})"""",
    """"eventTimestamp"{1,20}:\s{0,100}"{1,20}({time}[^"]{1,2000})"""",
    """"fileName"{1,20}:\s{0,100}"{1,20}({file_name}[^"]{1,2000}?(\.({file_ext}[^\."]{1,2000}))?)"""",
    """"fileCategory"{1,20}:\s{0,100}"{1,20}({file_type}[^"]{1,2000})"""",
    """"fileSize"{1,20}:\s{0,100}({bytes}\d{1,100})""",
    """"osHostName"{1,20}:\s{0,100}"{1,20}({dest_host}[^"]{1,2000})"""",
    """"eventType":"({alert_type}[^"]{1,2000})""",
    """"emailSender":"{1,20}({sender}[^"@]{1,2000}@[^"]{1,2000})"""",
    """"emailRecipients":\[*"{1,20}({recipient}[^"@]{1,2000}@[^"]{1,2000})"""",
    """"emailSubject":\[*"{1,20}({subject}[^"]{1,2000})"""",
	
  ]
  DupFields = ["sender->email_user", "recipient->recipients" ]


}
```