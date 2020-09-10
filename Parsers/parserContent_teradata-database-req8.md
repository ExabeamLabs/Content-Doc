#### Parser Content
```Java
{
Name = teradata-database-req8
  Vendor = Teradata
  Product = Teradata RDBMS
  Lms = Splunk
  DataType = "database-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""teradata""", """[TERADATA]""", """REQ8"""]
  Fields = [
     """exabeam_host=([^=]+@\s*)?({host}\S+)""",
     """({task_id}REQ8)[\s(#)]*({site_id}[^\s]+)[\s(#)]*({user}[^\s]+)[\s(#)]*({os_user}[^\s]+)[\s(#)]*({time}\d\d\d\d-\d\d-\d\d\s*\d\d:\d\d:\d\d)[\s(#)]*(?:Unavailable|({src_ip}[A-Fa-f:\d.]+))[\s(#)]*({session_id}[\d,]+)[\s(#)]*({query_id}\d+)[\s(#)]*({db_query}[^;]+)"""
  ]
}
```