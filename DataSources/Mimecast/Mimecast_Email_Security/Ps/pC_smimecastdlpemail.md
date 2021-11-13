#### Parser Content
```Java
{
Name = s-mimecast-dlp-email
    Vendor = Mimecast
    Product = Mimecast Email Security
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """|Dir=""", """|Sender=""", """|Rcpt=""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """datetime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\d\d[+-].+?)\|""",
      """\|aCode=(|({alert_id}[^\|]{1,2000}?))\|""",
      """\|Dir=(|({direction}[^\|]{1,2000}?))\|""",
      """\|Act=(|({action}[^\|]{1,2000}?))\|""",
      """\|Delivered=(|({action}[^\|]{1,2000}?))\|""",
      """\|RejType=\\(|({outcome_type}.+?))\\\|""",
      """\|Err=\\?(|({outcome}.+?))\\?\|""",
      """\|Error=\\?(|({outcome}.+?))\\?\|""",
      """\|RejInfo=\\?(|({outcome}.+?))\\?\|""",
      """\|Sender=(|<>|({sender}\S+?@\S+?))\|""",
      """\|headerFrom=(|<>|({sender}\S+?@\S+?))\|""",
      """\|Rcpt=(|<>|({recipient}\S+?@\S+?))\|""",
      """\|Rcpt=(|<>|({recipients}\S+?))\|""",
      """\|Subject=\\?(|({subject}.+?))\s{0,100}\\?\|""",
      """\|Snt=({bytes}\d{1,100})\|""",
      """\|SpamScore=({spam_score}\d{1,100})""",
      """\|IP=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    ]


}
```