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
  Conditions = [ """Alert based on rule ID""", """Database Name:""", """Protocol Version:""" ]
  Fields = [
    """Session start:\s{0,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\w+\s{1,100}\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\s{0,100}({host}[\w\.-]{1,2000})""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """rule ID\s{0,100}({alert_name}.+?)\s{0,100}([#\d\\n]{1,2000})?([\w\s]{1,2000}:)""",
    """rule ID\s{0,100}({alert_name}.+?)\s{0,100}-\s{0,100}Severity""",
    """Severity\s{0,100}({alert_severity}[^\s]{1,2000})\s""",
    """Category:\s{0,100}({alert_type}\S+)\s{0,100}Classification:""",
    """SQL:\s{0,100}({additional_info}.+?)?\s{0,100}SQL""",
    """Client:\s{0,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}(\((\()?({src_host}[\w\d\\]{1,2000})\))?""",
    """Server:\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}(\(({dest_host}[\w\d\\]{1,2000})\))?""",
    """Server Type:\s{0,100}({server_group}.+?)\s([#\d\\n]{1,2000})?Client:""",
    """DB User:\s{0,100}(({domain}\w+)\\)?({db_user}[\w\d]{1,2000})(\s{1,100}\(.+?\))?([#\d\\n]{1,2000})?([\w\s]{1,2000}:)""",
    """OS User:\s{0,100}({user}.+?)\s{0,100}([#\d\\n]{1,2000})?([\w\s]{1,2000}:)""",
    """Source Program:\s{0,100}({process}({directory}.+)[\\\/]({process_name}.+?))\s([#\d\\n]{1,2000})?SQL:""",
    """Database Name:\s{1,100}({database_name}.+?)\s{1,100}([#\d\n]{1,2000})?([\w\s]{1,2000}:)"""
  ]
  DupFields = [ "db_user->account","directory->process_directory" ]
}
```