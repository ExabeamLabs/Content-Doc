#### Parser Content
```Java
{
Name = json-github-app-activity
  Vendor = GitHub
  Product = GitHub
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ ""","action":"""", ""","remote_ip":"""", """"key":"namespace_id",""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"action":"({activity}[^"]{1,2000})""",
    """"remote_ip":"({src_ip}[^"]{1,2000})""",
    """"username":"({user}[^"]{1,2000})""",
    """"status":({result}[^,"]{1,2000})""",
    """"path":"({additional_info}[^"]{1,2000})""",
    """"user_id":({user_id}[^,"]{1,2000})""",
    """"key":"project_id".+?"value":"({object}[^"]{1,2000})""",
    """"target_branch":"({object}[^"]{1,2000})""",
    """"source_branch":"({object}[^"]{1,2000})""",
  ]
}
```