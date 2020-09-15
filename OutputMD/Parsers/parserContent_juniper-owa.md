#### Parser Content
```Java
{
Name = juniper-owa
  Vendor = Juniper Networks
  Product = Juniper OWA
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "AUT22670", "Login succeeded for" ]
  Fields = [
    """\sfw=({host}[\w\-\.]+)""",
    """\w+\s*\d+\s*\d\d:\d\d:\d\d\s+({host}[\w.\-]+)\s*\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d""",
    """\stime="+({time}\d+-\d+-\d+ \d+:\d+:\d+).+?user""",
    """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s""",
    """user=({user}.+?)\s+realm=""",
    """realm="+({app}[^"]+)""",
    """agent=.*?({browser}Trident/7.0)""",
    """agent="+({user_agent}[^"]+)"""",
    """agent=.*?({os}Windows[^;)]*)""",
    """agent=.*?Mozilla[^\s]+\s*\(({os}[^\)]+).*({browser}[\d.]+\s+(Mobile )?Safari)""",
    """agent=[^\s]+\s+\(((Windows|X11|Macintosh|U|compatible);( (U|I);)?\s+)?({os}[^;\)]+).*\s({browser}(Chrome|Firefox)/\d+)""",
    """agent=.*({browser}MSIE\s+\d[^\s,;\)]+)"""
  ]
}
```