#### Parser Content
```Java
{
Name = onapsis-db-op
    Vendor = Onapsis
  Product = Onapsis
    Lms = Direct
    DataType = "database-update"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """, db_table=""", """, action=""", """, user_name=""", """, user_id=""" ]
    Fields = [
      """<.*?>\w+ \d{1,2} \d{1,2}:\d{1,2}:\d{1,2} ({host}[\w\.-]{1,2000}?) ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
      """, user_name=\s{0,100}({user}[^,]{1,2000}?)\s{0,100},""",
      """, user_id=\s{0,100}({user_id}[^,]{1,2000}?)\s{0,100},""",
      """, action=\s{0,100}({db_operation}[^,]{1,2000}?)\s{0,100},""",  
      """, db_table\s{0,100}=({table_name}[^,]{1,2000}?)\s{0,100},""",
      """, ({additional_info}change\..+change\..+?="{1,20}.+?"{1,20})"""
      """, request_id=\s{0,100}({alert_id}[^,]{1,2000}?)\s{0,100},""",
    ]
    DupFields = [ "host->dest_host" ]
  }
```