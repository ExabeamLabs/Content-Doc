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
    """exabeam_host=({host}[\w.\-]+)""",
    """datetime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\s*\d\d:\d\d[+-]\d+)\|""",
    """\|aCode=(|({alert_id}[^\|]+?))\|""",
    """\|Act=(|({action}[^\|]+?))\|""",
    """\|MsgId=<?({message_id}[^>\|]+)(>|\|)""",
    """\|Sender=(|<>|({sender}\S+?@({external_domain}\S+?)))\|""",
    """\|SourceIP=({src_ip}[a-fA-F:\d\.]+)""",
    """\|Recipient=(|<>|({recipient}[^\|]+))\|""",
    """\|Subject=\\?(|({subject}[^\|$]+?))\s*(\||$)""",
    """\|AttNames=({attachments}[^\|]+?),?\s*\|""",
    """\|Route=(|({direction}[^\|]+?))\|"""
  ]
}
```