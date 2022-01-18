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
  Conditions = [ """<Event xmlns=""", """<Provider Name ='MSSQL""", """<Keyword>Audit ""","""<Binary>""" ]
  Fields = [
    """<TimeCreated SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """<EventID Qualifiers=[^>]{1,2000}>({event_code}\d{1,100})""",
    """<Provider Name ='({database_name}[^']{1,2000})'""",
    """<Computer>({host}[^<]{1,2000})<\/Computer>""",
    """<Message>({additional_info}[^<]{1,2000})""",
    """<Keyword>({outcome}Audit[^<]{1,2000})<\/Keyword>""",
    """<Message>.+?user\s'((({domain}[^\\']{1,2000})\\)?({user}[^']{1,2000}))'""",
    """\[CLIENT:\s{1,100}({src_ip}[a-fA-F\d:\.]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```