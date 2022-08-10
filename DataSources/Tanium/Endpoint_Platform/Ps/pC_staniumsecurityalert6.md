#### Parser Content
```Java
{
Name = s-tanium-security-alert-6
  Vendor = Tanium
  Product = Endpoint Platform
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"Intel Name":"Vulnerable Log4j MD5 Hashes"""", """"source":"tanium-index"""", """"MITRE Techniques":"""" ]
  Fields = [
    """"Timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""",
    """"Computer Name":"({src_host}[^"]{1,2000}?)"""",
    """"Computer IP":"({src_ip}[a-fA-F\d\.:]{1,2000})"""",
    """"Intel Id":({alert_id}\d{1,20})""",
    """"Intel Type":"({alert_type}[^"]{1,2000})"""",
    """"Intel Name":"({alert_name}[^"]{1,2000})"""",
    """"source":"({log_source}[^"]{1,2000})"""",
    """properties":\{"fullpath":"({process}({process_directory}[^"]{1,2000}?)\\{1,20}({process_name}[^"\\]{1,2000}))""""
  ]


}
```