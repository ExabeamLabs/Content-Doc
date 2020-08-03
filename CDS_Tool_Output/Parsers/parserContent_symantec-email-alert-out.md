#### Parser Content
```Java
{
Name = symantec-email-alert-out
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """protocol=SMTP""","""incident_id=""", """sender=""", """recipient=""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w.\-]+)\s+incident_id=""",
    """recipient=({recipient}[^,@]+@({external_domain}[^,]+)),""",
    """sender=({sender}[^,]+),""",
    """Subject=({subject}.+?)\s*,(\s+\w+=|\s*$)""",
    """blocked=({outcome}\w+)""",
    """Attachment_Filename=({attachments}.+?)\s*,(\s+\w+=|\s*$)""",
    """incident_id=({alert_id}\d+)""",
    """protocol=({protocol}.*?)\s+\w+="""
  ]
  DupFields = [ "recipient->recipients", "recipient->external_address" ]
}
```