#### Parser Content
```Java
{
Name = messagelabs-email-out
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "epoch"
  Conditions = ["""emailInfo""","""HELOString""",""""isOutbound":true"""]
  Fields = [
    """exabeam_host=([^@=]+@\s*)?({host}[\w.\-]+)""",
    """"mailProcessingStartTime"+:({time}\d+)""",
    """"headerFrom":"({sender}[^"]+)",""",
    """"subject":"({subject}[^"]+)",""",
    """"messageSize":({bytes}\d+)""",
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