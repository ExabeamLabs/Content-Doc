#### Parser Content
```Java
{
Name = s-guardium-db-alert-1
  Vendor = IBM
  Product = Infosphere Guardium
  Lms = Splunk
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "Alert based on rule ID", "Database Name:", "Protocol Version:" ]
  Fields = [
    """Session start:\s*({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s+\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s*({host}[\w\.-]+)""",
    """rule ID\s*({alert_name}.+?)\s*([#\d\\n]+)?([\w\s]+:)""",
    """rule ID\s*({alert_name}.+?)\s*-\s*Severity""",
    """Severity\s*({alert_severity}[^\s]+)\s""",
    """Category:\s*({alert_type}.+?)\s*Classification:""",
    """SQL:\s*({additional_info}.+?)?\s*SQL""",
    """Client:\s*({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(\(({src_host}[\w\d\\]+)\))?""",
    """Server:\s*({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(\(({dest_host}[\w\d\\]+)\))?""",
    """Server Type:\s*({server_group}.+?)\s([#\d\\n]+)?Client:""",
    """DB User:\s*({db_user}[\w\d\\]+)([#\d\\n]+)?([\w\s]+:)""",
    """OS User:\s*({user}.+?)\s*([#\d\\n]+)?([\w\s]+:)""",
    """Source Program:\s*({process}({directory}.+)[\\\/]({process_name}.+?))\s([#\d\\n]+)?SQL:"""
  ]
  DupFields = [ "db_user->account","directory->process_directory" ]
}
```