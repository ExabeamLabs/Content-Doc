#### Parser Content
```Java
{
Name = json-fireeye-alert-network
  Vendor = FireEye
  Product = FireEye Network Security (Helix)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"type":"fireeye_rule"""", """"threat_type":""", """"category":"Network"""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """"created_at":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """message":"({alert_name}[^"]+)""",
    """"severity":"({alert_severity}[^"]+)""",
    """"threat_type":({alert_type}\d+)""",
    """"source":"({src_ip}[a-fA-F\d.:]+)""",
    """"destination":"({dest_ip}[a-fA-F\d.:]+)""",
    """"protocol":"({protocol}[^"]+)""",
    """"srcdomain":"({additional_info}[^"]+)""",
    """"username":"(system_user|({user}[^"]+))""",
    """"description":"({policy}[^"]+)"""
  ]
}
```