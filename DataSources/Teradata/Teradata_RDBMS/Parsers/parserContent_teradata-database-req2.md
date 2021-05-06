#### Parser Content
```Java
{
Name = teradata-database-req2
  Vendor = Teradata
  Product = Teradata RDBMS
  Lms = Splunk
  DataType = "database-query"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""teradata""", """[TERADATA]""", """REQ2"""]
  Fields = [
  """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({task_id}REQ2)[\s(#)]{0,4}({site_id}\S+)[\s(#)]{0,4}({user}\S+)[\s(#)]{0,4}({account}\S+)[\s(#)]{0,4}({time}\d\d\d\d-\d\d-\d\d\s*\d\d:\d\d:\d\d)[\s(#)]{0,4}(?:Unavailable|({src_ip}[A-Fa-f:\d.]+))[\s(#)]{0,5}({session_id}[\d,]+)[\s(#)]{0,4}({query_id}\d+)[\s(#)]{0,4}({db_operation}\S+)[\s(#)]{0,4}({db_query}[^;]+)"""
  ]
}
```