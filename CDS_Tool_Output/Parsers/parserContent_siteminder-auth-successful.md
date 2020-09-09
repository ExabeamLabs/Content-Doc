#### Parser Content
```Java
{
Name = siteminder-auth-successful
  Vendor = SiteMinder
  Lms = Direct
  DataType = "authentication-successful"
  TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
  Conditions = [ """AuthAccept """, """,o=""", """;authlevel=""" ]
  Fields = [
    """({outcome}AuthAccept) ({host}[\w\-.]+) \[({time}\d+\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d+)\] "({src_ip}[A-Fa-f:\d.]+)""",
    """cn=({user}[^\s,]+),ou=({domain}[^,]+),o=({group}[^,"]+).*?"\s+"({web_domain}\S+)\s+({method}\S+)\s+({uri_path}[^"\?]+)(\?({uri_query}[^"]+))?"""",
    """uid=({user}[^\s,]+),o=({group}[^,]+),dc=({domain}[^,]+),.*?" "({app}.+?) \S+ ({resource}[^"\s]+)" \[.+?""",
    """authlevel=({auth_level}[^;\]]+)"""
  ]
}
```