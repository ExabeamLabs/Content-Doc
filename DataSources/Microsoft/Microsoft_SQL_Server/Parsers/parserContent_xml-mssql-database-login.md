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
    """<Data>\s{0,100}\[CLIENT:\s{0,100}({src_ip}[a-fA-F\d.:]+)""",
    """<Computer>({src_host}.+?)<\/Computer>.*?<Data>\s{0,100}\[CLIENT:\s{0,100}[^\]]*?local machine""",
    """<Data>\s{0,100}\[CLIENT:\s{0,100}[^\]]*?local machine.*?\].*?<Computer>({src_host}.+?)<\/Computer>""",
    """Connection made using ({auth_package}[^.]+).""",
    """<EventID Qualifiers=[^>]+>({event_code}\d{1,100})""",
    """<Keyword>({outcome}Audit.+?)</Keyword>""",
    """<Message>[^<>]*?Reason:\s{0,100}({reason}[^.]+?)\."""
    """\sserver_principal_name:(({domain}[^\\]+)\\)?({user}[^\s]+)\sserver_principal_sid""",
    """database_name:({database_name}[^\s]+)""",
    """\Wserver_principal_name:(({domain}[^\\\/]+?)[\\\/])?({db_user}[^\\\/\s]+?)(\s{1,100}\w+:|\s{0,100}$)""",
    """\Waction_id:({db_operation}[^\s]+)""",
    """schema_name:({database_schema}[^\s]+)""",
    """\Wobject_name:({table_name}[^\s]+)""",
    """\Wstatement:(|-- network|Login failed.+?|Network error code.+?|({db_query}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    
  ]
  DupFields = [ "host->dest_host" ]
}
```