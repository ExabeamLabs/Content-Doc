#### Parser Content
```Java
{
Name = q-o365-dlp-email
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = QRadar
  DataType = "dlp-email-alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """@{Status=""", """; SenderAddress=""" ]
  Fields = [
    """({host}[\w.\-]+)\s{1,100}(\S+\s{1,100}){4}@\{Status=""",
    """Status=({outcome}[^;]+)""",
    """Received=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """SenderAddress=({sender}[^;@]+@({external_domain_sender}[^;]+))""",
    """RecipientAddress=({recipient}[^;@]+@({external_domain_recipient}[^;]+))""",
    """RecipientAddress=({recipients}[^;]+)""",
    """Size=({bytes}\d{1,100})""",
    """Subject=({subject}.+?)\s{0,100}\}""",
  ]
}
```