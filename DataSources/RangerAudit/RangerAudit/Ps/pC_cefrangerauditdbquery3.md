#### Parser Content
```Java
{
Name = cef-rangeraudit-db-query-3
  Product = RangerAudit
  Conditions = [ """"RangerAudit"""", """access""", """"USE"""" ]
}
cef-rangeraudit-db-query = {
  Vendor = RangerAudit
  Lms = ArcSight
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS"
  Fields = [
    """evtTime"{0,20}:"({time}[^"]{1,2000})""",
    """agentHost"{0,20}:"({host}[^"]{1,2000})""",
    """repo"{0,20}:"({app}[^"]{1,2000})""",
    """reqUser"{0,20}:"({user}[^"]{1,2000})""",
    """access"{0,20}:"({db_operation}[^"]{1,2000})""",
    """reqData"{0,20}:"({db_query}[^"]{1,2000})""",
    """resource"{0,20}:"\/?({database_name}[^"\/]{1,2000})""",
    """cliIP"{0,20}:"({src_ip}[^"]{1,2000})""",
    """resType"{0,20}:"({resource}[^"]{1,2000})""",
    """result"{0,20}:"{0,20}({outcome}[^",]{1,2000})""",
  ]
  DupFields = [ "db_operation->activity", "db_query->additional_info" ]}
```