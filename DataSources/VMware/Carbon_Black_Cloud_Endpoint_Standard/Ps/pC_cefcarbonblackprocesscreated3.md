#### Parser Content
```Java
{
Name = cef-carbonblack-process-created-3
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = """epoch"""
  Conditions = [  """threatIndicators""", """"eventType":"CREATE_PROCESS"""", """ invoked """, """parentPrivatePid":""""]
  Fields = [
    """exabeam_host=({host}[\w\-\.]{1,2000})""",
    """"eventTime":({time}\d{1,20}),""",
    """"deviceIpAddress":"({src_ip}[A-Fa-f:\d\.]{1,2000})"""",
    """"deviceName":"(({domain}[^\\]{1,2000})\\{1,20})?({src_host}[^"]{1,2000}?)"""",
    """"email":"(({domain}[^\\\s"]{1,2000})\\{1,20})?(HiveStreamingService|SYSTEM|({user}[^@"]{1,2000}))"""",
    """"eventType":"({alert_name}[^"]{1,2000})"""",
    """"applicationName":"({process_name}[^"]{1,2000})"""",
    """"targetPriorityType":"({alert_severity}[^"]{1,2000})"""",
    """"shortDescription":"({additional_info}[^,]{1,2000})",""",
    """"applicationPath":"({process}(({directory}[^"]{1,2000}?)[\\\/]{1,20})?({process_name}[^\/\\"]{1,2000}))"""",
    """"name":"({file_path}(\w:|\\\\)[^"]{1,2000})"""",
    """"name":"({file_name}[^\\\/"]{1,2000}?(\.({file_ext}[^"]{1,2000}))?)"""",
    """"name":"({file_parent}(\w:|\\\\)[^"]{1,2000})\\{1,20}(?:[^\\"]{1,2000}?)"""",
    """"targetApp":\{[^}]{1,2000}"sha256Hash":"({sha256}[^"]{1,2000})"""",
    """"targetApp":\{[^}]{1,2000}"md5Hash":"({md5}[^"]{1,2000})"""",
  ]
  DupFields = ["directory->process_directory", "alert_name->alert_type"]


}
```