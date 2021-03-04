#### Parser Content
```Java
{
Name = q-oracle-db-query
  Vendor = Oracle
  Lms = QRadar
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """Oracle Audit""", """ ACTION :""", """ DATABASE USER:""", """CLIENT USER:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """({host}[\w\-.]+)\s+Oracle Audit""",
    """ACTION\s+:\[\d+\]\s+'({db_query}({db_operation}\w+)\s*.*?)\s*'\s+DATABASE USER:""",
    """ACTION\s+:\[\d+\]\s+'({db_operation}grant \w+)""",
    """ACTION\s+:\[\d+\]\s+'({db_operation}revoke \w+)""",
    """ACTION\s+:\[\d+\]\s+'({db_operation}alter \w+)""",
    """\sCLIENT USER:\[\d+\]\s*'({user}[^']+)'""",
    """\sDBID:\[\d+\]\s*'(|({database_name}[^']+))'""",
    """\sDATABASE USER:\[\d+\]\s*'(\/|({account}[^'\\\/\s]+))'""",
    """\sPRIVILEGE:\[\d+\]\s*'({privilege}[^']+)'""",
  ]
  DupFields = [ "user->os_user", "account->db_user" ]
}
```