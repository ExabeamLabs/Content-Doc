#### Parser Content
```Java
{
Name = googlecloud-web-activity
  Vendor = Google
  Product = GCP Squid Proxy
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"jsonPayload":""", """"gce_instance"""", """googleapis.com""", """resource_name""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"bytes":"({bytes}\d{1,100})""",
    """"client":"(-|({src_ip}[^"]+))""",
    """"method":"(-|({method}[^"]+))""",
    """"cache":"({proxy_action}[^"]+)""",
    """"status":"({result_code}\d{1,100})""",
    """"url":"({full_url}[^"]+)""",
    """"user":"({user}[^"]+)""",
    """"project_id":"({project_id}[^"]+)""",
    """"logName":".+squid_({action}[^"]+)""",
    """"hierarchy_target":"(-|({dest_ip}[^"]+))""",
    """"zone":"(-|({zone}[^"]+))""",
    """"instance_id":"(-|({host}[^"]+))"""
  ]
}
```