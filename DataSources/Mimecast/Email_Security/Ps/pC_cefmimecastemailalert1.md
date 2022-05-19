#### Parser Content
```Java
{
Name = cef-mimecast-email-alert-1
  Vendor = Mimecast
  Product = Email Security
  Lms = ArcSight
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """destinationServiceName =Mimecast Email Security""", """"acc":"""", """"Route":"""", """"aCode":"""", """"Subject":""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z) ([\w.\-]{1,2000}) """,
    """"(?i)Route":"({direction}[^"]{1,2000})""",
    """"(?:id|aCode)":"({alert_id}[^"]{1,2000})""",
    """"(recipientAddress|Recipient)":"({recipient}[^"]{1,2000})""",
    """(senderAddress|Sender)":"(<>|({sender}[^"]{1,2000}))""",
    """"(?i)Subject":"({subject}[^"]{1,2000}?)\s{0,100}"""",
    """"(messageId|MsgId)":"({message_id}[^"]{1,2000})""",
    """"(?:action|actions)":"({outcome}[^"]{1,2000})""",
    """"actionTriggered":"({outcome}[^"]{1,2000})""",
    """"acc":"({user}[^"]{1,2000})""",
    """"SourceIP":"({src_ip}[^"]{1,2000})""""
  ]
  DupFields = ["recipient->user_email", "recipient->email_user"]


}
```