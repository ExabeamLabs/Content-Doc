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
    """<Provider Name='({database_name}[^']{1,2000})'""",
    """<Computer>({host}.+?)<\/Computer>""",
    """<EventData><Data>(({domain}[^\\\/<>]{1,2000}?)[\\\/]{1,2000})?({user}[^\\\/]{1,2000}?)</Data>""",
    """<Data>\s{0,100}\[CLIENT:\s{0,100}({src_ip}[a-fA-F\d.:]{1,2000})""",
    """<Computer>({src_host}.+?)<\/Computer>.*?<Data>\s{0,100}\[CLIENT:\s{0,100}[^\]]{0,2000}?local machine""",
    """<Data>\s{0,100}\[CLIENT:\s{0,100}[^\]]{0,2000}?local machine.*?\].*?<Computer>({src_host}.+?)<\/Computer>""",
    """Connection made using ({auth_package}[^.]{1,2000}).""",
    """<EventID Qualifiers=[^>]{1,2000}>({event_code}\d{1,100})""",
    """<Keyword>({outcome}Audit.+?)</Keyword>""",
    """<Message>[^<>]{0,2000}?Reason:\s{0,100}({reason}[^.]{1,2000}?)\."""
    """\sserver_principal_name:(({domain}[^\\]{1,2000})\\)?({user}[^\s]{1,2000})\sserver_principal_sid""",
    """database_name:({database_name}[^\s]{1,2000})""",
    """\Wserver_principal_name:(({domain}[^\\\/]{1,2000}?)[\\\/])?({db_user}[^\\\/\s]{1,2000}?)(\s{1,100}\w+:|\s{0,100}$)""",
    """\Waction_id:({db_operation}[^\s]{1,2000})""",
    """schema_name:({database_schema}[^\s]{1,2000})""",
    """\Wobject_name:({table_name}[^\s]{1,2000})""",
    """\Wstatement:(|-- network|Login failed.+?|Network error code.+?|({db_query}.+?))(\s{1,100}\w+:|\s{0,100}$)""",
    
  ]
  DupFields = [ "host->dest_host" ]
}
```