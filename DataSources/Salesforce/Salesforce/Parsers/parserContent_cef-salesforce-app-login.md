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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",  
    """LoginTime\\=({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """suser=(({domain}[^\\\s@;=]+)\\+)?(system|({user}[^\\\=\s;@]+))\s{1,100}(\w+=|$)""",
    """suser=({user_email}[^\\\=\s;@]+@({email_domain}[^\\\=\s;@]+))""",
    """suser=({user_email}[^\\\=\s;@]+@[^\\\=\s;@]+)""",
    """SourceIp\\*=({src_ip}[A-Fa-f:\d.]+)""",
    """Status\\*=({outcome}[^;]+)""",
    """Platform\\*=({os}[^;]+)""",
    """TlsProtocol\\*=({protocol}[^;]+)""",
    """Browser\\*=(Unknown|({browser}.+?))(;|\s\w+=)""",
    """dvchost=({src_host}.+?)\s{0,100}(\w+=|$)""",
    """({app}Sales Cloud)""",
    """cs1=({auth_method}[^\s]+)""",
    """UserId\\*=({user_id}[^;]+)""",
    """LoginGeo\.City\\*=({location_city}[^;]+)""",
    """LoginGeo\.Country\\*=({location_country}[^;]+)""",
    """LoginType\\*=({login_type}[^;]+)""",
    """LoginUrl\\*=({url_host}[^;]+)""",
  ]
}
```