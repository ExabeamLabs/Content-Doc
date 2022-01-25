#### Parser Content
```Java
{
Name = cef-mimecast-security-alert
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """CEF:""", """Mimecast Email Security""", """dproc=Attachment Protection""", """"recipientAddress":"""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"date":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\+\d{1,100})""",
    """dproc=({dproc}[^=]{1,2000}?)\s{1,100}\w+=""", 
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"(?i)Route":"({direction}[^"]{1,2000})""",
    """"(?:id|aCode)":"({alert_id}[^"]{1,2000})""",
    """"(recipientAddress|Recipient)":"({recipient}[^"]{1,2000})""",
    """(senderAddress|Sender)":"(<>|({sender}[^@"]{1,2000}@({external_domain}[^"]{1,2000})))""",
    """"(?i)Subject":"({subject}[^"]{1,2000}?)\s{0,100}"""",
    """"(messageId|MsgId)":"({message_id}[^"]{1,2000})""",
    """"fileName":"({file_name}[^"]{1,2000})""",
    """"fileType":"({file_type}[^"]{1,2000})""",
    """"fileHash":"({md5}[^"]{1,2000})""",
    """"(?:action|actions)":"({outcome}[^"]{1,2000})""",
    """"actionTriggered":"(none|({outcome}[^"]{1,2000}))""",
    """"acc":"({user}[^"]{1,2000})""",
    """"SenderDomain":"(<>|({external_domain}[^"]{1,2000}))"""",
    """"SourceIP":"({src_ip}[^"]{1,2000})"""",
    """"result":"({outcome}[^"]{1,2000})""",
    """"subject":"({subject}[^"]{1,2000})"""
  ]


}
```