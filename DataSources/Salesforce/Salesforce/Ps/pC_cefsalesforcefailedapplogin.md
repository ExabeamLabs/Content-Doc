#### Parser Content
```Java
{
Name = cef-salesforce-failed-app-login
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Skyformation|SkyFormation Cloud Apps Security|""", """|login-failed|""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """LoginTime\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """suser=(({domain}[^\\\s@;=]{1,2000})\\+)?(system|({user}[^\\\=\s;@]{1,2000}))\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]{1,2000}@[^\\\=\s;@]{1,2000})""",
    """SourceIp\\=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Status\\=({outcome}[^;]{1,2000})""",
    """Status\\=({failure_reason}[^;]{1,2000})""",
    """Platform\\=({os}[^;]{1,2000})""",
    """TlsProtocol\\=({protocol}[^;]{1,2000})""",
    """Browser\\=({browser}.+?)\s{0,100}(\w+=|$)""",
    """dvchost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]


}
```