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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """"action":"({activity}[^"]+)""",
    """"remote_ip":"({src_ip}[^"]+)""",
    """"username":"({user}[^"]+)""",
    """"status":({result}[^,"]+)""",
    """"path":"({additional_info}[^"]+)""",
    """"user_id":({user_id}[^,"]+)""",
    """"key":"project_id".+?"value":"({object}[^"]+)""",
    """"target_branch":"({object}[^"]+)""",
    """"source_branch":"({object}[^"]+)""",
  ]
}
```