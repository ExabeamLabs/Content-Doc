#### Parser Content
```Java
{
Name = q-oracle-db-query
  Vendor = Oracle
  Product = Oracle DB
  Lms = QRadar
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Oracle Audit""", """ ACTION :""", """ DATABASE USER:""", """CLIENT USER:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[A-Fa-f:\d.]{1,2000})""",
    """\Wdvchost=({host}[\w\-.]{1,2000})""",
    """({host}[\w\-.]{1,2000})\s{1,100}Oracle Audit""",
    """ACTION\s{1,100}:\[\d{1,100}\]\s{1,100}'({db_query}({db_operation}\w+)\s{0,100}.*?)\s{0,100}'\s{1,100}DATABASE USER:""",
    """ACTION\s{1,100}:\[\d{1,100}\]\s{1,100}'({db_operation}grant \w+)""",
    """ACTION\s{1,100}:\[\d{1,100}\]\s{1,100}'({db_operation}revoke \w+)""",
    """ACTION\s{1,100}:\[\d{1,100}\]\s{1,100}'({db_operation}alter \w+)""",
    """\sCLIENT USER:\[\d{1,100}\]\s{0,100}'({user}[^']{1,2000})'""",
    """\sDBID:\[\d{1,100}\]\s{0,100}'(|({database_name}[^']{1,2000}))'""",
    """\sDATABASE USER:\[\d{1,100}\]\s{0,100}'(\/|({account}[^'\\\/\s]{1,2000}))'""",
    """\sPRIVILEGE:\[\d{1,100}\]\s{0,100}'({privilege}[^']{1,2000})'""",
  ]
  DupFields = [ "user->os_user", "account->db_user" ]
}
```