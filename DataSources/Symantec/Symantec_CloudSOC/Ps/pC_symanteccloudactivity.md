#### Parser Content
```Java
{
Name = symantec-cloud-activity
  Vendor = Symantec
  Product = Symantec CloudSOC
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""destinationServiceName =Symantec CloudSOC""" ]
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"inserted_timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""""
    """suser=({user_email}[^\s]{1,2000}@.+?)\s\w+=""",
    """"user_name":"({user_fullname}[^"]{1,2000})""",
    """"user":"({user_email}[^\@]{1,2000}@({email_domain}[^"]{1,2000}))""",
    """"user":"(system|({user_email}[^\@]{1,2000}@[^"]{1,2000}))""",
    """"service":"({app}[^"]{1,2000})"""",
    """"browsers":(\[)?"({browser}[^"]{1,2000})"""",
    """"user_agent":"({user_agent}[^"]{1,2000})"""",
    """"activity_type":"({activity}[^"]{1,2000})"""",
    """"ioi_code":"({alert_type}[^"]{1,2000})"""",
    """"message":"({additional_info}[^"]{1,2000})"""",
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"object_type":"({object_type}[^"]{1,2000})"""",
    """"object_name":"(|\/|({object}({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000}\\\/)?(|({file_name}[^\\\/=]{0,2000}?(\.({file_ext}[^"]{1,2000}))?)?))))""""
    """"name":"(|\/|({object}({file_path}({file_parent}[^=]{0,2000}?[\\\/]{1,2000}\\\/)?(|({file_name}[^\\\/=]{0,2000}?(\.({file_ext}[^"]{1,2000}))?)?))))""""
    """"host(s)?":"({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})"""",
    """ext__shared_with_=({target}[^\s]{1,2000})\s\w+="""
  ]
  DupFields = ["file_path->resource", "app->service", "activity->accesses"]


}
```