#### Parser Content
```Java
{
Name = s-O365-email
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Splunk
  DataType = "dlp-email-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Conditions = [ """DateStamp=""", """MessageTraceID=""" ]
  Fields = [
    """Received="({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\.\d\d\d)""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """Index="({alert_id}\d{1,100})"""",
    """Status="({outcome}[^"]{1,2000})"""",
    """Subject="({subject}[^"]{1,2000})"""",
    """SenderAddress="({sender}[^"]{1,2000})"""",
    """RecipientAddress="({recipients}[^"]{1,2000})"""",
    """RecipientAddress="({external_address}[^",]{1,2000})"""",
    """RecipientAddress="[^@]{1,2000}@({external_domain}[^",]{1,2000})"""",
    """FromIP="({src_ip}[^"]{1,2000})"""",
    """ToIP="({dest_ip}[^"]{1,2000})"""",
    """Size="({bytes}\d{1,100})"""",
    """({alert_name}Office365)""",
    """({alert_type}o365_mail)""",
  ]


}
```