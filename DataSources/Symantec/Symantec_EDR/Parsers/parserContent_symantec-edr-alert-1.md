#### Parser Content
```Java
{
Name = symantec-edr-alert-1
  Vendor = Symantec
  Product = Symantec EDR
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"product_name":"SymantecEDR:Endpoint""", """downloaded_portal_id"""", """data_source_url_referer""" ]
  Fields = [
    """"device_time":"({time}[^"]+)"""",
    """"user_name":"({user}[^"]+)"""",
    """"device_name":"({host}[^"]+)"""",
    """"host_name":"({src_host}[^"]+)"""",
    """"domain_name":"({domain}[^"]+)"""",
    """"device_ip":"({dest_ip}[^"]+)"""",
    """"data_source_ip":"({src_ip}[^"]+)"""",
    """"folder":"({file_path}[^"]+)"""",
    """"data_source_url":"({malware_url}[^"]+)"""",
    """"name":"({file_name}[^"]+)"""",
  ]
  DupFields = ["file_name -> alert_name"]
}
```