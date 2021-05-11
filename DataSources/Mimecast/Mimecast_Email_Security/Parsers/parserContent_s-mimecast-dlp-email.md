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
      """exabeam_host=({host}[\w.\-]+)""",
      """datetime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\s{0,100}\d\d:\d\d[+-].+?)\|""",
      """\|aCode=(|({alert_id}[^\|]+?))\|""",
      """\|Dir=(|({direction}[^\|]+?))\|""",
      """\|Act=(|({action}[^\|]+?))\|""",
      """\|Delivered=(|({action}[^\|]+?))\|""",
      """\|RejType=\\(|({outcome_type}.+?))\\\|""",
      """\|Err=\\?(|({outcome}.+?))\\?\|""",
      """\|Error=\\?(|({outcome}.+?))\\?\|""",
      """\|RejInfo=\\?(|({outcome}.+?))\\?\|""",
      """\|Sender=(|<>|({sender}\S+?@({external_domain_sender}\S+?)))\|""",
      """\|headerFrom=(|<>|({sender}\S+?@({external_domain_sender}\S+?)))\|""",
      """\|Rcpt=(|<>|({recipient}\S+?@({external_domain_recipient}\S+?)))\|""",
      """\|Rcpt=(|<>|({recipients}\S+?))\|""",
      """\|Subject=\\?(|({subject}.+?))\s{0,100}\\?\|""",
      """\|Snt=({bytes}\d{1,100})\|""",
      """\|SpamScore=({spam_score}\d{1,100})""",
      """\|IP=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    ]
}
```