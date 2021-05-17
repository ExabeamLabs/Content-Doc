#### Parser Content
```Java
{
Name = json-fireeye-alert-network
  Vendor = FireEye
  Product = FireEye Helix
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"type":"fireeye_rule"""", """"threat_type":""", """"category":"Network"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """"created_at":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """message":"({alert_name}[^"]{1,2000})""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"threat_type":({alert_type}\d{1,100})""",
    """"source":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"destination":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"protocol":"({protocol}[^"]{1,2000})""",
    """"srcdomain":"({additional_info}[^"]{1,2000})""",
    """"username":"(system_user|({user}[^"]{1,2000}))""",
    """"description":"({policy}[^"]{1,2000})"""
  ]
}
```