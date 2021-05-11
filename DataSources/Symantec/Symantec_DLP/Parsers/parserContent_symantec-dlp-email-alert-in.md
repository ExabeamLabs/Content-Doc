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
    """exabeam_host=({host}[\w.\-]+)""",
    """, data-sent=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}(\+|\-)\d{1,100})""",
    """^.*?, Last Name=(|({user_lastname}[^,]+?))(,|\})""",
    """^.*?, First Name=(|({user_firstname}[^,]+?))(,|\})""",
    """, attachment-name1=(|({attachment}[^,]+?))(,|\})""",
    """, sender-email=(|(\w+:/+)?({sender}[^,:@]+?@({external_domain}[^@,:]+?)))(,|\})""",
    """, monitor-host=(|({host}[^,]+?))(,|\})""",
    """, subject=(|({subject}[^,]+?))\s{0,100}(,|\})""",
    """, protocol=(|({protocol}[^,]+?))(,|\})""",
    """, recipient-email1=(|(\w+:/+)?({recipient}[^,:@]+?@[^,:@]+?))(,|\})""",
    """\+\d{1,100};\w+;({attachments}[^;]+;([^;]*;){3}([^;]+;){0,8})""",
  ]
  DupFields = [ "sender->external_address" ]
}
```