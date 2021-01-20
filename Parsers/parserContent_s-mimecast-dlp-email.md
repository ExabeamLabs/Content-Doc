#### Parser Content
```Java
{
Name = s-mimecast-dlp-email
    Vendor = Mimecast
  Product = Email Security
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [ """|Dir=""", """|Sender=""", """|Rcpt=""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]+)""",
      """datetime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[+-].+?)\|""",
      """\|aCode=(|({alert_id}.+?))\|""",
      """\|Dir=(|({direction}.+?))\|""",
      """\|Act=(|({action}.+?))\|""",
      """\|Delivered=(|({action}.+?))\|""",
      """\|RejType=\\(|({outcome_type}.+?))\\\|""",
      """\|Err=\\(|({outcome}.+?))\\\|""",
      """\|Error=\\(|({outcome}.+?))\\\|""",
      """\|RejInfo=\\(|({outcome}.+?))\\\|""",
      """\|Sender=(|<>|({sender}\S+?@({external_domain_sender}\S+?)))\|""",
      """\|headerFrom=(|<>|({sender}\S+?@({external_domain_sender}\S+?)))\|""",
      """\|Rcpt=(|<>|({recipient}\S+?@({external_domain_recipient}\S+?)))\|""",
      """\|Rcpt=(|<>|({recipients}\S+?))\|""",
      """\|Subject=\\({subject}.+?)\\\|""",
      """\|Snt=({bytes}\d+)\|""",
    ]
  }
```