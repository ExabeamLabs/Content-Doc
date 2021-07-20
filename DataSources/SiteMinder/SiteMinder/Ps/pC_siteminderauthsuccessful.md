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
    """({outcome}AuthAccept) ({host}[\w\-.]{1,2000}) \[({time}\d{1,100}\/\w+\/\d\d\d\d:\d\d:\d\d:\d\d [+-]\d{1,100})\] "({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """cn=({user}[^\s,]{1,2000}),ou=({domain}[^,]{1,2000}),o=({group}[^,"]{1,2000}).*?"\s{1,100}"({web_domain}\S+)\s{1,100}({method}\S+)\s{1,100}({uri_path}[^"\?]{1,2000})(\?({uri_query}[^"]{1,2000}))?"""",
    """uid=({user}[^\s,]{1,2000}),o=({group}[^,]{1,2000}),dc=({domain}[^,]{1,2000}),.*?" "({app}.+?) \S+ ({resource}[^"\s]{1,2000})" \[.+?""",
    """authlevel=({auth_level}[^;\]]{1,2000})"""
  ]
}
```