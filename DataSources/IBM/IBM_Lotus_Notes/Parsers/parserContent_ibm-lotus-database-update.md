#### Parser Content
```Java
{
Name = ibm-lotus-database-update
  Vendor = IBM
  Product = IBM Lotus Notes
  Lms = Direct
  DataType = "database-update"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = ["""  Updating '""", """' into database '""", """' from template '"""]
  Fields = [
    """({time}\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d (am|AM|PM|pm))""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """Updating .*? into database '({database_name}[^']{1,2000})"""
  ]
}
```