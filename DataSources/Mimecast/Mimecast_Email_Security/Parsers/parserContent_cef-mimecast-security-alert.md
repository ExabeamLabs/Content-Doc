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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"date":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\+\d{1,100})""",
    """dproc=({dproc}[^=]+?)\s{1,100}\w+=""", 
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"(?i)Route":"({direction}[^"]+)""",
    """"(?:id|aCode)":"({alert_id}[^"]+)""",
    """"(recipientAddress|Recipient)":"({recipient}[^"]+)""",
    """(senderAddress|Sender)":"(<>|({sender}[^@"]+@({external_domain}[^"]+)))""",
    """"(?i)Subject":"({subject}[^"]+?)\s{0,100}"""",
    """"(messageId|MsgId)":"({message_id}[^"]+)""",
    """"fileName":"({file_name}[^"]+)""",
    """"fileType":"({file_type}[^"]+)""",
    """"fileHash":"({md5}[^"]+)""",
    """"(?:action|actions)":"({outcome}[^"]+)""",
    """"actionTriggered":"({outcome}[^"]+)""",
    """"acc":"({user}[^"]+)""",
    """"SenderDomain":"(<>|({external_domain}[^"]+))"""",
    """"SourceIP":"({src_ip}[^"]+)"""",
    """"result":"({outcome}[^"]+)""",
    """"subject":"({subject}[^"]+)"""
  ]
}
```