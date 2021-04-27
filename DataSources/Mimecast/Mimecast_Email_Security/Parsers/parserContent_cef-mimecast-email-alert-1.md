#### Parser Content
```Java
{
Name = cef-mimecast-email-alert-1
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """CEF:""", """Mimecast Email Security""", """dproc=SIEM Logs""", """"acc":"""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z) ({host}[\w.\-]+) Skyformation""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]+)""",
    """"(?i)Route":"({direction}[^"]+)""",
    """"(?:id|aCode)":"({alert_id}[^"]+)""",
    """"(recipientAddress|Recipient)":"({recipient}[^"]+)""",
    """(senderAddress|Sender)":"(<>|({sender}[^"]+))""",
    """"(?i)Subject":"({subject}[^"]+?)\s*"""",
    """"(messageId|MsgId)":"({message_id}[^"]+)""",
    """"(?:action|actions)":"({outcome}[^"]+)""",
    """"actionTriggered":"({outcome}[^"]+)""",
    """"acc":"({user}[^"]+)""",
    """"SenderDomain":"(<>|({external_domain}[^"]+))"""",
    """"SourceIP":"({src_ip}[^"]+)""""
  ]
  DupFields = ["recipient->user_email", "recipient->email_user"]
}
```