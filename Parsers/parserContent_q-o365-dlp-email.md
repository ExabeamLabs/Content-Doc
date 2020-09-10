#### Parser Content
```Java
{
Name = q-o365-dlp-email
  Vendor = Microsoft
  Product = Office 365
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """@{Status=""", """; SenderAddress=""" ]
  Fields = [
    """({host}[\w.\-]+)\s+(\S+\s+){4}@\{Status=""",
    """Status=({outcome}[^;]+)""",
    """Received=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """SenderAddress=({sender}[^;@]+@({external_domain_sender}[^;]+))""",
    """RecipientAddress=({recipient}[^;@]+@({external_domain_recipient}[^;]+))""",
    """RecipientAddress=({recipients}[^;]+)""",
    """Size=({bytes}\d+)""",
    """Subject=({subject}.+?)\s*\}""",
  ]
}
```