#### Parser Content
```Java
{
Name = mimecast-dlp-email
  Vendor = Mimecast
  Product = Mimecast Email Security
  Lms = Direct
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """|aCode=""", """|Sender=""", """|Subject=""", """|acc=""", """|MsgId=""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """datetime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\d\d[+-]\d{1,100})\|""",
    """\|aCode=(|({alert_id}[^\|]{1,2000}?))\|""",
    """\|Act=(|({action}[^\|]{1,2000}?))\|""",
    """\|MsgId=<?({message_id}[^>\|]{1,2000})(>|\|)""",
    """\|Sender=(|<>|({sender}\S+?@\S+?))\|""",
    """\|SourceIP=({src_ip}[a-fA-F:\d\.]{1,2000})""",
    """\|Recipient=(|<>|({recipient}[^\|]{1,2000}))\|""",
    """\|Subject=\\?(|({subject}[^\|$]{1,2000}?))\s{0,100}(\||$)""",
    """\|AttNames=({attachments}[^\|]{1,2000}?),?\s{0,100}\|""",
    """\|Route=(|({direction}[^\|]{1,2000}?))\|""",
    """AttCnt=({attachment_count}\d{1,100})""",
    """MsgSize=({bytes}\d{1,100})"""
  ]
}
```