#### Parser Content
```Java
{
Name = s-fireeye-hx-alert-6
    Vendor = FireEye
    Product = FireEye Endpoint Security (HX)
    Lms = Splunk
    DataType = "network-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Conditions = [ """"hostname":""", """"event_at":""", """"event_type":""", """"ipv4NetworkEvent"""", """"ipv4NetworkEvent/remoteIP":""", """"alert_id":""", """"ipv4NetworkEvent/username":""" ]
    Fields = [
       """"event_at":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
       """"alert_id":\s{0,100}({alert_id}\d{1,100})""",
       """"event_type":\s{0,100}"({alert_name}[^"]{1,2000})""",
       """"ipv4NetworkEvent/remoteIP":\s{0,100}"({dest_ip}[\da-fA-F.:]{1,2000})""",
       """"ipv4NetworkEvent/remotePort":\s{0,100}({dest_port}\d{1,100})""",
       """"hostname":\s{0,100}"({host}[^"]{1,2000})""",
       """"ipv4NetworkEvent/processPath":\s{0,100}"({process}[^"]{1,2000})""",
       """"ipv4NetworkEvent/process":\s{0,100}"({process_name}[^"]{1,2000})""",
       """"ipv4NetworkEvent/protocol":\s{0,100}"({protocol}[^"]{1,2000})""",
       """"ipv4NetworkEvent/localIP":\s{0,100}"({src_ip}[\da-fA-F.:]{1,2000})""",
       """"ipv4NetworkEvent/localPort":\s{0,100}({src_port}\d{1,100})""",
       """"ipv4NetworkEvent/username":\s{0,100}"(({domain}[^"\\\/]{1,2000})[\\\/]{1,2000})?({user}[^"]{1,2000})"""
    ]      
    DupFields = ["alert_name->alert_type"]
  

}
```