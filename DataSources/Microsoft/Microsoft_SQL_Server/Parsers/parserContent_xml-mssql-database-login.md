#### Parser Content
```Java
{
Name = xml-mssql-database-login
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Event xmlns=""", """<Provider Name='MSSQL""", """<Keyword>Audit """ ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<Provider Name='({database_name}[^']+)'""",
    """<Computer>({host}.+?)<\/Computer>""",
    """<EventData><Data>(({domain}[^\\\/<>]+?)[\\\/]+)?({user}[^\\\/]+?)</Data>""",
    """<Data>\s*\[CLIENT:\s*({src_ip}[a-fA-F\d.:]+)""",
    """<Computer>({src_host}.+?)<\/Computer>.*?<Data>\s*\[CLIENT:\s*[^\]]*?local machine""",
    """<Data>\s*\[CLIENT:\s*[^\]]*?local machine.*?\].*?<Computer>({src_host}.+?)<\/Computer>""",
    """Connection made using ({auth_package}[^.]+).""",
    """<EventID Qualifiers='({event_code}\d+)""",
    """<Keyword>({outcome}Audit.+?)</Keyword>""",
    """<Message>[^<>]*?Reason:\s*({reason}[^.]+?)\."""
  ]
  DupFields = [ "host->dest_host" ]
}
```