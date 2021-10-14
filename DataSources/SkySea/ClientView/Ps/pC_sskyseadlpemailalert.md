#### Parser Content
```Java
{
Name = s-skysea-dlp-email-alert
  Vendor = SkySea
  Product = ClientView
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy/MM/dd HH:mm:ss"
  Conditions = [ """,メール,""" ]
  Fields = [
    """({host}[\w\-.]{1,2000}),\d{1,100},({src_host}[\w\-.]{1,2000}),({src_ip}[A-Fa-f:\d.]{1,2000}),[^,]{0,2000},({user}[^\s,]{1,2000}),(|({user_fullname}[^,\(\（]{1,2000}(\（[^\）,]{1,2000}\）)?)[^,]{0,2000}),({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100}),([^,]{0,2000},){4}\s{0,100}(|({subject}[^,]{1,2000}?))\s{0,100},([^,]{0,2000},){21}(({recipients}<?({recipient}[^,;<>\s@]{1,2000}@[^,;>\s@]{1,2000})[^,]*)|[^,]{0,2000}),(<?({sender}[^,;\s@>]{1,2000}@[^,;\s@>]{1,2000})>?|[^,]{0,2000}),\s{0,100}(|({attachments}[^,]{1,2000}?))\s{0,100},""",
  ]
}
```