#### Parser Content
```Java
{
Name = leef-mssql-database-login-1
  DataType = "database-login"
  Conditions = [ """LEEF""", """ 18453 """, """Login succeeded""", """application=MSSQL""" ]
  Fields = ${MicrosoftParserTemplates.leef-mssql-login.Fields} [
    """({event_name}Login succeeded)""",
  ]

leef-mssql-login = {
    Vendor = Microsoft
    Product = SQL Server
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZZZ"
    Fields = [
      """devTime=({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\w{1,3})""",
      """resource=({host}[^=]{1,2000}?)\s\w+=""",
      """LEEF\s({event_code}\d{1,100})""",
      """usrName =(N\/A|(({domain}[^\\\s]{1,2000})\\{1,20})?({user}[^\s]{1,2000}))""",
      """message=({additional_info}[^\[]{1,2000})\.\s{1,100}\[""",
      """message=[^']{1,2000}?\Wuser\s'(({domain}[^\\']{1,2000})\\{1,20})?({user}[^']{1,2000})""",
      """CLIENT:\s{1,100}({src_ip}[a-fA-F\d:.]{1,2000})""",
      """application=({app}[^=]{1,2000}?)\s{1,100}\w+="""
    ]
    DupFields = ["host->dest_host"
}
```