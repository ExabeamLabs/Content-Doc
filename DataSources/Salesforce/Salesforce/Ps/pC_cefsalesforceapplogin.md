#### Parser Content
```Java
{
Name = cef-salesforce-app-login
  Vendor = Salesforce
  Product = Salesforce
  Lms = ArcSight
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """SkyFormation Cloud Apps Security|""", """|login-success|""", """Sales Cloud""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",  
    """LoginTime\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """suser=(({domain}[^\\\s@;=]{1,2000})\\+)?(system|({user}[^\\\=\s;@]{1,2000}))\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]{1,2000}@({email_domain}[^\\\=\s;@]{1,2000}))""",
    """suser=({user_email}[^\\\=\s;@]{1,2000}@[^\\\=\s;@]{1,2000})""",
    """SourceIp\\*=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """Status\\*=({outcome}[^;]{1,2000})""",
    """Platform\\*=({os}[^;]{1,2000})""",
    """TlsProtocol\\*=({protocol}[^;]{1,2000})""",
    """Browser\\*=(Unknown|({browser}.+?))(;|\s\w+=)""",
    """dvchost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
    """cs1=({auth_method}[^\s]{1,2000})""",
    """UserId\\*=({user_id}[^;]{1,2000})""",
    """LoginGeo\.City\\*=({location_city}[^;]{1,2000})""",
    """LoginGeo\.Country\\*=({location_country}[^;]{1,2000})""",
    """LoginType\\*=({login_type}[^;]{1,2000})""",
    """LoginUrl\\*=({url_host}[^;]{1,2000})""",
  ]
}
```