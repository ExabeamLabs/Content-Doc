#### Parser Content
```Java
{
Name = xml-mssql-database-login-1
  Vendor = Microsoft
  Product = Microsoft SQL Server
  Lms = Direct
  DataType = "database-login"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """<Event xmlns=""", """<Provider Name='MSSQL""", """<Keyword>Audit ""","""<Binary>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID Qualifiers=[^>]+>({event_code}\d{1,100})""",
    """<Provider Name='({database_name}[^']+)'""",
    """<Computer>({host}[^<]+)<\/Computer>""",
    """<Message>({additional_info}[^<]+)""",
    """<Keyword>({outcome}Audit[^<]+)<\/Keyword>""",
    """<Message>.+?user\s'((({domain}[^\\']+)\\)?({user}[^']+))'""",
    """\[CLIENT:\s{1,100}({src_ip}[a-fA-F\d:\.]+)"""
  ]
  DupFields = [ "host->dest_host" ]
}
```