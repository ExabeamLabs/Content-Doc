#### Parser Content
```Java
{
Name = onapsis-db-op
    Vendor = Onapsis
    Lms = Direct
    DataType = "database-update"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """, db_table=""", """, action=""", """, user_name=""", """, user_id=""" ]
    Fields = [
      """<.*?>\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} ({host}[\w\.-]+?) ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
      """, user_name=\s*({user}[^,]+?)\s*,""",
      """, user_id=\s*({user_id}[^,]+?)\s*,""",
      """, action=\s*({db_operation}[^,]+?)\s*,""",  
      """, db_table\s*=({table_name}[^,]+?)\s*,""",
      """, ({additional_info}change\..+change\..+?="+.+?"+)"""
      """, request_id=\s*({alert_id}[^,]+?)\s*,""",
    ]
    DupFields = [ "host->dest_host" ]
  }
 
  {
    Name = securelink-app-login
    Vendor = SecureLink
    Product = SecureLink
    Lms = QRadar
    DataType = "app-login"
    TimeFormat = "epoch"
    Conditions = [ "SecureLink:","AUDIT:","""connected to Application"""]
    Fields = [
      """exabeam_endTime=({time}\d+)""",
      """exabeam_host=({host}[^\s]+)""",
      """connected to Application ({app}[^.]+)""",
      """AUDIT:.+?\(({user_emailId}[^)]+)\)"""
    ]
  }
```