#### Parser Content
```Java
{
Name = pan-fw-packet-logs
    Vendor = Palo Alto Networks
    Product = NGFW
    Lms = Direct
    DataType = "network-connection"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Conditions = [ """packet_log""", """as_name=""", """as_num=""", """direction=""" ]
    Fields = [
      """exabeam_host=({host}[\w.\-]{1,2000})""",
      """packet_log: ({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}(-|\+)\d{4})""" 
      """\saction=({outcome}.*?)(,\s\w+=|$)"""
      """\sproto=({protocol}.*?)(,\s\w+=|$)"""
      """\sdirection=({direction}.*?)(,\s\w+=|$)"""
      """\sreason=({additional_info}.*?)(,\s\w+=|$)"""
      """\ssrc=(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({src_host}[^\s]{1,2000}?))(,\s\w+=|$)"""
      """\sdst=(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|({dest_host}[^\s]{1,2000}?))(,\s\w+=|$)"""
      """\ssrc_port=({src_port}\d{1,100})"""
      """\sdst_port=({dest_port}\d{1,100})"""
    ]
  }
```