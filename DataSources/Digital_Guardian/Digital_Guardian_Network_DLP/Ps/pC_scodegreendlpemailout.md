#### Parser Content
```Java
{
Name = s-codegreen-dlp-email-out
  Vendor = Digital Guardian
  Product = Digital Guardian Network DLP
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss z"
  Conditions = [ """protocol="SMTP"""", """email_subject=""", "exabeam_raw" ]
  Fields = [
    """timestamp="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d \w+)"""",
    """\d\d:\d\d ({host}[^\s]{1,2000})\s{1,100}\d{1,100}\s{1,100}\d{4}\-\d\d\-\d\d""",
    """source="(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^"\\;]{1,2000}))"""",
    """email_sender="(?:|({sender}[^"\\]{1,2000}))"""",
    """email_recipients="({external_address}[^";]{1,2000})""",
    """email_recipients="[^@]{1,2000}@({external_domain}[^";]{1,2000})""",
    """email_recipients="({recipients}.+?)"""",
    """inspected_document="(?:|({file_name}.+?))"""",
    """inspected_document="(?:|({attachment}.+?))"""",
    """inspected_document="[^"]{1,2000}\.({extension}[^\s"\/]{1,2000})""",
    """email_subject="({subject}.+?)"""",
    """({alert_type}SMTP)""",
    """source_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """destination_ip="({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """matched_policies_by_severity="({alert_severity}[^"]{1,2000})""",
    """matched_policies_by_severity="\w+:({alert_name}[^,;\/]{1,2000})""",
    """({direction}o)""",
    """action_taken="(?:|({outcome}[^"]{1,2000}))""""
  ]


}
```