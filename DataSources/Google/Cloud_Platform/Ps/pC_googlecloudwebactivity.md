#### Parser Content
```Java
{
Name = googlecloud-web-activity
  Vendor = Google
  Product = Cloud Platform
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"jsonPayload":""", """"gce_instance"""", """googleapis.com""", """resource_name""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"bytes":"({bytes}\d{1,100})""",
    """"client":"(-|({src_ip}[^"]{1,2000}))""",
    """"method":"(-|({method}[^"]{1,2000}))""",
    """"cache":"({proxy_action}[^"]{1,2000})""",
    """"status":"({result_code}\d{1,100})""",
    """"url":"({full_url}[^"]{1,2000})""",
    """"user":"({user}[^"]{1,2000})""",
    """"project_id":"({project_id}[^"]{1,2000})""",
    """"logName":".+squid_({action}[^"]{1,2000})""",
    """"hierarchy_target":"(-|({dest_ip}[^"]{1,2000}))""",
    """"zone":"(-|({zone}[^"]{1,2000}))""",
    """"instance_id":"(-|({host}[^"]{1,2000}))"""
  ]


}
```