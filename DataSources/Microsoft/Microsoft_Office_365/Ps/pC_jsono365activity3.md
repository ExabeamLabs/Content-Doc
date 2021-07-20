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
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"CreationTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"Operation":"({activity}[^"]{1,2000})""",
    """"UserId":"({user_email}[^@]{1,2000}@({email_domain}[^",]{1,2000}))"""",
    """"Workload":"({app}[^"]{1,2000})"""",
    """"ObjectId":"({object}[^"]{1,2000})""",
    """"Id":"({object_id}[^"]{1,2000})"""",
    """"UserKey":"([^@]{1,2000}@[^"]{1,2000}|(({domain}[^\\]{1,2000})[\\]{1,2000}({user}[^"]{1,2000}))|({=user}[^"]{1,2000}))"""",
    """"RecordType":({object_type}[^,]{1,2000}),""",
    """"ClientIP":"({src_ip}[^"]{1,2000})"""",
    """"SourceFileName":"({file_name}[^"]{1,2000})"""",
    """"SourceRelativeUrl":"({file_path}[^"]{1,2000})"""",
    """"SourceFileExtension":"({file_ext}[^"]{1,2000})"""",
    """"UserAgent":"({user_agent}[^"]{1,2000})""""
  ]
  DupFields = ["activity->operation"]
}
```