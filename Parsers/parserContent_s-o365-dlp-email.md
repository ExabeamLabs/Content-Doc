#### Parser Content
```Java
{
Name = s-O365-dlp-email
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"RecipientAddress"""", """"SenderAddress"""", """"MessageTraceId"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"Received"+:\s*"+({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d+)""",
    """"DateReceived":\s*"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\dZ)""",
    """"RecipientAddress"+:\s*"+[^@]+@({external_domain_recipient}[^",]+)""",
    """"RecipientAddress"+:\s*"+({recipients}[^",]+)"""",
    """"RecipientAddress"+:\s*"+({recipient}[^"\s,;]+)""",
    """"SenderAddress"+:\s*"+(<>|\\+|({sender}[^">,]+))""",
    """"MessageId"+:\s*"+({message_id}[^",]+)"""",
    """"SenderAddress"+:\s*"+[^@]+@({external_domain_sender}[^",]+)""",
    """"ToIP"+:\s*"+?(?:null|({dest_ip}[a-fA-F\d.:]+))""",
    """"FromIP"+:\s*"+?(?:null|({src_ip}[a-fA-F\d.:]+))""",
    """"Subject"+:\s*(?:"+|"+({subject}.+?)\s*)"+,\s*"""",
    """"Size"+:\s*"?({bytes}\d+)""",
    """"Status"+:\s*"+({outcome}[^",]+)"""",
    """"Organization"+:"+({host}[^",]+)""",
    """"MessageTraceId"+:\s*"+({alert_id}[^",]+)""",
    """src-account-name":"({account_name}[^"]+)"""
  ]
}
```