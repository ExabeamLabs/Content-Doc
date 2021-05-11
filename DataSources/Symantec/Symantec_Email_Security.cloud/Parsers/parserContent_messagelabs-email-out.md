#### Parser Content
```Java
{
Name = messagelabs-email-out
  Vendor = Symantec
  Product = Symantec Email Security.cloud
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = ["""emailInfo""","""HELOString""",""""isOutbound":true"""]
  Fields = [
    """exabeam_host=([^@=]+@\s{0,100})?({host}[\w.\-]+)""",
    """"mailProcessingStartTime"{1,20}:({time}\d{1,100})""",
    """"headerFrom":"({sender}[^"]+)",""",
    """"subject":"({subject}[^"]+)",""",
    """"messageSize":({bytes}\d{1,100})""",
    """"messageId":"({alert_id}[^"]+)",""",
    """"headerTo":\[({recipients}[^\]]+)\],""",
    """"headerTo":\["({recipient}[^"@]+@({external_domain}[^@"]+))"""",
    """"isOutbound":({direction}[^,]+),""",
    """"senderIp":"({src_ip}[a-fA-F\d.:]+)""",
    """\[\{"fileNameOrURL":"({file_name}[^\.]+\.({file_ext}[^"]+))""",
  ]
  DupFields = [ "sender->email_user", "sender->user_email", "recipient->external_address" , "file_name->attachment"]
}
```