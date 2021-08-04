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
    """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}[\w.\-]{1,2000})""",
    """"mailProcessingStartTime"{1,20}:({time}\d{1,100})""",
    """"headerFrom":"({sender}[^"]{1,2000})",""",
    """"subject":"({subject}[^"]{1,2000})",""",
    """"messageSize":({bytes}\d{1,100})""",
    """"messageId":"({alert_id}[^"]{1,2000})",""",
    """"headerTo":\[({recipients}[^\]]{1,2000})\],""",
    """"headerTo":\["({recipient}[^"@]{1,2000}@({external_domain}[^@"]{1,2000}))"""",
    """"isOutbound":({direction}[^,]{1,2000}),""",
    """"senderIp":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\[\{"fileNameOrURL":"({file_name}[^\.]{1,2000}\.({file_ext}[^"]{1,2000}))""",
  ]
  DupFields = [ "sender->email_user", "sender->user_email", "recipient->external_address" , "file_name->attachment"]
}
```