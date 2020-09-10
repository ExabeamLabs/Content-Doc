#### Parser Content
```Java
{
Name = messagelabs-email-out
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""emailInfo""","""HELOString""",""""isOutbound":true"""]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}[\w.\-]+)""",
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"headerFrom":"({sender}[^"]+)",""",
    """"subject":"({subject}[^"]+)",""",
    """"messageSize":({bytes}\d+)""",
    """"messageId":"({alert_id}[^"]+)",""",
    """"headerTo":\[({recipients}[^\]]+)\],""",
    """"headerTo":\["({recipient}[^"@]+@({external_domain}[^@"]+))"""",
    """"isOutbound":({direction}[^,]+),""",
    """"senderIp":"({src_ip}[a-fA-F\d.:]+)"""
  ]
  DupFields = [ "sender->email_user", "sender->user_email", "recipient->external_address" ]
}
```