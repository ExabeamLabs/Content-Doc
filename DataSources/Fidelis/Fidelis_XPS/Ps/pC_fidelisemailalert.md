#### Parser Content
```Java
{
Name = fidelis-email-alert
  Vendor = Fidelis
  Product = Fidelis XPS
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Fidelis XPS""" , """Protocol=""" , """Sensor="""]
  Fields = [
        """Time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
        """\w+ \d{1,100} \d\d:\d\d:\d\d\s({host}[\w\-.]{1,2000})\sProduct""",
        """\sDestIP="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
        """From=({sender}[^\s]{1,2000})\s""",
        """User=(?!(<n\/a>))({email_user}[^\s]{1,2000})\s""",
        """To=({recipient}[^,\n\s]{1,2000})""",
        """To=({recipients}[^\n\s]{1,2000})"""
        """SrcIP="({src_ip}[^"]{1,2000})"""",
        """Severity="({alert_severity}[^"]{1,2000})"""",
        """Filename="(?!(<n\/a>))({attachments}[^"]{1,2000})"""",
        """Filename="(?!(<n\/a>))({attachment}[^\.]{1,2000}({file_ext}[^"]{1,2000}))("|,)""",
        """Protocol="({protocol}[^"]{1,2000})"""",
        """Rule="({alert_type}[^"]{1,2000})"""",
        """SrcPort="({src_port}[^"]\d{1,100})"""",
        """DestPort="({dest_port}[^"]\d{1,100})""""
          ]
  DupFields = [ "email_user->user_email" ]


}
```