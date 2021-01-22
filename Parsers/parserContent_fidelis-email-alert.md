#### Parser Content
```Java
{
Name = fidelis-email-alert
  Vendor = Fidelis
  Product = Fidelis
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [  """Fidelis XPS""" , """Protocol=""" , """Sensor="""]
  Fields = [
        """Time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)"""
        """\w+ \d+ \d\d:\d\d:\d\d\s({host}[\w\-.]+)\sProduct""",
        """\sDestIP="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
        """From=({sender}[^\s]+)\s""",
        """From=[^@]+@({external_domain_sender}.+?)\s+(\w+=|$)"""
        """User=(?!(<n\/a>))({email_user}[^\s]+)\s""",
        """To=({recipient}[^,\n\s]+)""",
        """To=({recipients}[^\n\s]+)"""
        """To=[^@]+@({external_domain_recipient}.+?)\s+(\w+=|$)"""
        """SrcIP="({src_ip}[^"]+)"""",
        """Severity="({alert_severity}[^"]+)"""",
        """Filename="(?!(<n\/a>))({attachments}[^"]+)"""",
        """Filename="(?!(<n\/a>))({attachment}[^"]+)("|,)""",
        """Protocol="({protocol}[^"]+)"""",
        """Rule="({alert_type}[^"]+)"""",
        """SrcPort="({src_port}[^"]\d+)"""",
        """DestPort="({dest_port}[^"]\d+)""""
          ]
  DupFields = [ "email_user->user_email" ]
}
```