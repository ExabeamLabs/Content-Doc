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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"date":"({time}\d+-\d+-\d+T\d+:\d+:\d+\+\d+)""",
    """dproc=({dproc}[^=]+?)\s+\w+=""", 
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"(?i)Route":"({direction}[^"]+)""",
    """"(?:id|aCode)":"({alert_id}[^"]+)""",
    """"(recipientAddress|Recipient)":"({recipient}[^"]+)""",
    """(senderAddress|Sender)":"(<>|({sender}[^@"]+@({external_domain}[^"]+)))""",
    """"(?i)Subject":"({subject}[^"]+?)\s*"""",
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