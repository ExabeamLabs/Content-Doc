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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """LoginTime\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """suser=(({domain}[^\\\s@;=]+)\\+)?(system|({user}[^\\\=\s;@]+))\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]+@[^\\\=\s;@]+)""",
    """SourceIp\\=({src_ip}[A-Fa-f:\d.]+)""",
    """Status\\=({outcome}[^;]+)""",
    """Status\\=({failure_reason}[^;]+)""",
    """Platform\\=({os}[^;]+)""",
    """TlsProtocol\\=({protocol}[^;]+)""",
    """Browser\\=({browser}.+?)\s{0,100}(\w+=|$)""",
    """dvchost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
  ]
}
```