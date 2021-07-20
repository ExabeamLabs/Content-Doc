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
    """"device_time":"({time}[^"]{1,2000})"""",
    """"user_name":"({user}[^"]{1,2000})"""",
    """"device_name":"({host}[^"]{1,2000})"""",
    """"host_name":"({src_host}[^"]{1,2000})"""",
    """"domain_name":"({domain}[^"]{1,2000})"""",
    """"device_ip":"({dest_ip}[^"]{1,2000})"""",
    """"data_source_ip":"({src_ip}[^"]{1,2000})"""",
    """"folder":"({file_path}[^"]{1,2000})"""",
    """"data_source_url":"({malware_url}[^"]{1,2000})"""",
    """"name":"({file_name}[^"]{1,2000})"""",
  ]
  DupFields = ["file_name -> alert_name"]
}
```