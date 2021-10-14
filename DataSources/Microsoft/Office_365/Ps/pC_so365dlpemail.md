#### Parser Content
```Java
{
Name = s-O365-dlp-email
  Vendor = Microsoft
  Product = Office 365
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"RecipientAddress"""", """"SenderAddress"""", """"MessageTraceId"""", """"Subject": """ ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"Received"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d{1,100})""",
    """"DateReceived":\s{0,100}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\dZ)""",
    """"RecipientAddress"{1,20}:\s{0,100}"{1,20}({recipients}[^",]{1,2000})"""",
    """"RecipientAddress"{1,20}:\s{0,100}"{1,20}({recipient}[^"\s,;]{1,2000})""",
    """"SenderAddress"{1,20}:\s{0,100}"{1,20}(<>|\\+|({sender}[^">,]{1,2000}))""",
    """"MessageId"{1,20}:\s{0,100}"{1,20}({message_id}[^",]{1,2000})"""",
    """"ToIP"{1,20}:\s{0,100}"{1,20}?(?:null|({dest_ip}[a-fA-F\d.:]{1,2000}))""",
    """"FromIP"{1,20}:\s{0,100}"{1,20}?(?:null|({src_ip}[a-fA-F\d.:]{1,2000}))""",
    """"Subject"{1,20}:\s{0,100}(?:"{1,20}|"{1,20}({subject}.+?)\s{0,100})"{1,20},\s{0,100}"""",
    """"Size"{1,20}:\s{0,100}"?({bytes}\d{1,100})""",
    """"Status"{1,20}:\s{0,100}"{1,20}({outcome}[^",]{1,2000})"""",
    """"Organization"{1,20}:"{1,20}({host}[^",]{1,2000})""",
    """"MessageTraceId"{1,20}:\s{0,100}"{1,20}({alert_id}[^",]{1,2000})""",
    """src-account-name":"({account_name}[^"]{1,2000})"""
  ]
}
```