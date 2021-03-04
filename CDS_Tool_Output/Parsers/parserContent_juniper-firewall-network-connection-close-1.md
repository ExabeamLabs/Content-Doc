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
      """exabeam_host=({host}[\w.\-]+)""",
      """({time}\w+ \d+ \d\d:\d\d:\d\d)\s+(|({host}\S+)\s+)RT_FLOW:\s+RT_FLOW_SESSION_CLOSE:\s+({failure_reason}[^:]+):\s+({src_ip}[a-fA-F\d.:]+)\/({src_port}\d+)\->({dest_ip}[a-fA-F\d.:]+)\/({dest_port}\d+)\s+(?:None|({protocol}\S+))\s+({src_translated_ip}[a-fA-F\d.:]+)\/({src_translated_port}\d+)(\S+\s+){4}({rule}\S+)\s+(\S+\s+){3}\d+\(({bytes_in}\d+)\)\s+\d+\(({bytes_out}\d+)\)\s+({session_duration}\d+)\s+(\S+\s+){2}(?:N\/A|({user}[^\(]+))\S+\s+({dest_interface}\S+)"""
      """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    ]
}
```