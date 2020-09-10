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
    """({host}[\w\-.]+),\d+,({src_host}[\w\-.]+),({src_ip}[A-Fa-f:\d.]+),[^,]*,({user}[^\s,]+),(|({user_fullname}[^,\(\（]+(\（[^\）,]+\）)?)[^,]*),({time}\d+\/\d+\/\d+ \d+:\d+:\d+),([^,]*,){4}\s*(|({subject}[^,]+?))\s*,([^,]*,){21}(({recipients}<?({recipient}[^,;<>\s@]+@({external_domain_recipient}[^,;>\s@]+))[^,]*)|[^,]*),(<?({sender}[^,;\s@>]+@({external_domain_sender}[^,;\s@>]+))>?|[^,]*),\s*(|({attachments}[^,]+?))\s*,""",
  ]
}
```