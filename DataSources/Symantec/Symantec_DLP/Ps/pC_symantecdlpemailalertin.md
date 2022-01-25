#### Parser Content
```Java
{
Name = symantec-dlp-email-alert-in
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """, attachment-name""", """, recipient-email1=""", """, sender-email=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """, data-sent=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d{1,100})""",
    """^.*?, Last Name =(|({user_lastname}[^,]{1,2000}?))(,|\})""",
    """^.*?, First Name =(|({user_firstname}[^,]{1,2000}?))(,|\})""",
    """, attachment-name1=(|({attachment}[^,]{1,2000}?))(,|\})""",
    """, sender-email=(|(\w+:/+)?({sender}[^,:@]{1,2000}?@({external_domain}[^@,:]{1,2000}?)))(,|\})""",
    """, monitor-host=(|({host}[^,]{1,2000}?))(,|\})""",
    """, subject=(|({subject}[^,]{1,2000}?))\s{0,100}(,|\})""",
    """, protocol=(|({protocol}[^,]{1,2000}?))(,|\})""",
    """, recipient-email1=(|(\w+:/+)?({recipient}[^,:@]{1,2000}?@[^,:@]{1,2000}?))(,|\})""",
    """\+\d{1,100};\w+;({attachments}[^;]{1,2000};([^;]{0,2000};){3}([^;]{1,2000};){0,8})""",
  ]
  DupFields = [ "sender->external_address" ]


}
```