#### Parser Content
```Java
{
Name = messagelabs-email-in
  Vendor = Symantec
  Product = Symantec Email Security.cloud
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = ["""emailInfo""","""HELOString""",""""isOutbound":false"""]
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}[\w.\-]+)""",
    """"mailProcessingStartTime"{1,20}:({time}\d{1,100})""",
    """"headerFrom":"({sender}[^"@]+@({external_domain}[^@"]+))",""",
    """"subject":"({subject}[^"]+)",""",
    """"messageSize":({bytes}\d{1,100})""",
    """"messageId":"({alert_id}[^"]+)",""",
    """"headerTo":\[({recipients}[^\]]+)\],""",
    """"headerTo":\["({recipient}[^"]+)"""",
    """"isOutbound":({direction}[^,]+),""",
    """"senderIp":"({src_ip}[a-fA-F\d.:]+)"""
  ]
  DupFields = [ "recipient->email_user", "recipient->user_email", "sender->external_address" ]
}
```