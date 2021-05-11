#### Parser Content
```Java
{
Name = s-mdam-db-query
  Vendor = McAfee
  Product = MDAM
  Lms = Splunk
  DataType = "database-query"
  IsHVF = true
  TimeFormat = "dd MMM yyyy HH:mm:ss"
  Conditions = [ """db_user=""", """db_type=""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[^\s]+)\s{1,100}(\w+=|$)""",
    """execution_time="({time}\d\d \w{3} \d{4} \d\d:\d\d:\d\d)""",
    """src_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """os_user="(NULL|(({domain}[^\\"]+)\\+)?({os_user}.+?)\s{0,100})"""",
    """cmdtype="({db_operation}[^"]+)"""",
    """sqlstmt="({db_query}.+?)\s{0,100}"{1,20}\s{0,100}(\w+=|$)""",
    """db_name="({database_name}[^"]+)"""",
    """src_host="({src_host}[^"]+)"""",
    """db_user="(NULL|(({db_domain}[^\\"]+)\\+)?({db_user}.+?)\s{0,100})"""",
    """schema="(NULL|({schema}[^"]+))"""",
    """db_type="({app}[^"]+)"""",
    """sid="({user_sid}[^"]+)"""",
    """accessed_objects="(NULL|({additional_info}[^"]+))""""
  ]
  DupFields = [ "db_user->account", "os_user->user" ]
}
```