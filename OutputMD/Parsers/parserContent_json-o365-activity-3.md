#### Parser Content
```Java
{
Name = json-o365-activity-3
  Vendor = Microsoft
  Product = Microsoft Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"Workload":"""", """"UserKey":"""", """"Operation":"""" ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Operation":"({activity}[^"]+)""",
    """"UserId":"({user_email}[^@]+@({email_domain}[^",]+))"""",
    """"Workload":"({app}[^"]+)"""",
    """"ObjectId":"({object}[^"]+)""",
    """"Id":"({object_id}[^"]+)"""",
    """"UserKey":"({user}[^"]+)"""",
    """"RecordType":({object_type}[^,]+),""",
    """"ClientIP":"({src_ip}[^"]+)"""",
    """"SourceFileName":"({file_name}[^"]+)"""",
    """"SourceRelativeUrl":"({file_path}[^"]+)"""",
    """"SourceFileExtension":"({file_ext}[^"]+)"""",
    """"UserAgent":"({user_agent}[^"]+)""""
  ]
  DupFields = ["activity->operation"]
}
```