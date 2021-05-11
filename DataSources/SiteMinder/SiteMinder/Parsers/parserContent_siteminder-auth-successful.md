#### Parser Content
```Java
{
Name = siteminder-auth-successful
  Vendor = SiteMinder
  Product = SiteMinder
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """AuthAccept """, """,o=""", """;authlevel=""" ]
  Fields = [
    """({outcome}AuthAccept) ({host}[\w\-.]+) \[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d{1,100})\] "({src_ip}[A-Fa-f:\d.]+)""",
    """cn=({user}[^\s,]+),ou=({domain}[^,]+),o=({group}[^,"]+).*?"\s{1,100}"({web_domain}\S+)\s{1,100}({method}\S+)\s{1,100}({uri_path}[^"\?]+)(\?({uri_query}[^"]+))?"""",
    """uid=({user}[^\s,]+),o=({group}[^,]+),dc=({domain}[^,]+),.*?" "({app}.+?) \S+ ({resource}[^"\s]+)" \[.+?""",
    """authlevel=({auth_level}[^;\]]+)"""
  ]
}
```