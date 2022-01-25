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
    """({host}[\w.\-]{1,2000})\s{1,100}(\S+\s{1,100}){4}@\{Status=""",
    """Status=({outcome}[^;]{1,2000})""",
    """Received=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """SenderAddress=({sender}[^;@]{1,2000}@[^;]{1,2000})""",
    """RecipientAddress=({recipient}[^;@]{1,2000}@[^;]{1,2000})""",
    """RecipientAddress=({recipients}[^;]{1,2000})""",
    """Size=({bytes}\d{1,100})""",
    """Subject=({subject}.+?)\s{0,100}\}""",
  ]


}
```