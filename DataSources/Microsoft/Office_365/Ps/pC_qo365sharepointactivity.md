#### Parser Content
```Java
{
Name = q-o365-sharepoint-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = QRadar
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """,Operation"""", """"Workload"""", """"SharePoint,""" ]
  Fields = [
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
    """,ItemType":"({file_type}[^,]{1,2000})""",
    """,Operation":"({accesses}[^,]{1,2000})""",
    """,SourceRelativeUrl":"({file_parent}[^",]{1,2000})""",
    """,ClientIP":"({src_ip}[A-Fa-f.\d:]{1,2000})""",
    """,UserAgent":"({user_agent}[^,]{1,2000})""",
    """"SourceFileExtension":"({file_ext}[^,]{1,2000})""",
    """,SourceFileName":"({file_name}[^,]{1,2000})""",
    """"Workload":"({app}[^,]{1,2000})""",
    ]
    DupFields = [ "accesses->activity", "file_name->object" ]   


}
```