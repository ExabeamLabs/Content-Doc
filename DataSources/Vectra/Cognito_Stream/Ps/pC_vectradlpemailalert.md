#### Parser Content
```Java
{
Name = vectra-dlp-email-alert
  DataType = "dlp-email-alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """COGNITO_STREAM""", """vectra_metadata_smtp""", """METADATA_SMTP""" ]
  Fields = ${VectraParserTemplates.vectra-meta-data.Fields} [
    """subject="({subject}[^"]{1,2000})"""",
    """mail_from="({sender}[^"@]{1,2000}@[^"]{1,2000})"""",
    """rcpt_to="({recipient}[^"@]{1,2000}@[^"]{1,2000})"""",
    """msgid="<({message_id}[^"]{1,2000})>""""
  ]

vectra-meta-data = {
  Vendor = Vectra
  Product = Cognito Stream
  Lms = Direct
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\sts="{1,20}({time}\d{1,100})""",
    """id.orig_h="{1,20}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"{1,20}"""
    """id.orig_p="{1,20}({src_port}\d{1,100})"{1,20}""",
    """id.resp_h="{1,20}({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"{1,20}""",
    """id.resp_p="{1,20}({dest_port}\d{1,100})"{1,20}""",
    """orig_hostname="{1,20}(null|((IP-)*((\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000})|({src_host}[^"]{1,2000}))))""""
    """resp_hostname="{1,20}(null|((IP-)*((\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000})|({dest_host}[^"]{1,2000}))))""""
  ]
 
}
```