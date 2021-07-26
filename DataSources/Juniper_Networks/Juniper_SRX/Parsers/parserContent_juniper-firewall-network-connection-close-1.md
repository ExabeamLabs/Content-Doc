#### Parser Content
```Java
{
Name = juniper-firewall-network-connection-close-1
    Vendor = Juniper Networks
    Product = Juniper SRX
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """RT_FLOW_SESSION_CLOSE:""", """session closed""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """({time}\w+ \d{1,100} \d\d:\d\d:\d\d)\s{1,100}(|({host}\S+)\s{1,100})RT_FLOW:\s{1,100}RT_FLOW_SESSION_CLOSE:\s{1,100}({failure_reason}[^:]{1,2000}):\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000})\/({src_port}\d{1,100})\->({dest_ip}[a-fA-F\d.:]{1,2000})\/({dest_port}\d{1,100})\s{1,100}(?:None|({protocol}\S+))\s{1,100}({src_translated_ip}[a-fA-F\d.:]{1,2000})\/({src_translated_port}\d{1,100})(\S+\s{1,100}){4}({rule}\S+)\s{1,100}(\S+\s{1,100}){3}\d{1,100}\(({bytes_in}\d{1,100})\)\s{1,100}\d{1,100}\(({bytes_out}\d{1,100})\)\s{1,100}({session_duration}\d{1,100})\s{1,100}(\S+\s{1,100}){2}(?:N\/A|({user}[^\(]{1,2000}))\S+\s{1,100}({dest_interface}\S+)"""
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    ]
}
```