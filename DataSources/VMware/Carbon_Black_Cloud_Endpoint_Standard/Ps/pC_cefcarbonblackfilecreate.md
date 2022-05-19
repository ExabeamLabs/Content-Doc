#### Parser Content
```Java
{
Name = cef-carbonblack-file-create
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "file-write"
  TimeFormat = "epoch"
  Conditions = [ """threatIndicators":""", """"eventType":"FILE_CREATE"""", """destinationServiceName =CB Defense""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"eventTime":({time}\d{1,20}),""",
    """"deviceIpAddress":"({src_ip}[a-fA-F\d:.]{1,2000})"""",
    """"deviceName":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({src_host}[^\\\s"]{1,2000})"""",
    """"email":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({user}[^"]{1,2000})""",
    """"eventType":"({alert_name}[^"]{1,2000})"""",
    """threatIndicators":\[?"({alert_type}[^"]{1,2000})""",
    """"applicationPath":"({process}(({directory}[^"=,]{1,2000})\\)?({process_name}[^\\"]{1,2000}))"""",
    """"applicationName":"({process_name}[^"]{1,2000})"""",
    """"targetPriorityType":"({alert_severity}[^"]{1,2000})"""",
    """"name":"({file_path}(\w:|\\\\)[^"]{1,2000})"""",
    """"name":"({file_parent}(\w:|\\\\)[^"]{1,2000}?)\\{1,20}(?:[^\\="]{1,2000}?)"""",
    """"name":"({file_path}(({file_parent}\w+:[^"]{1,2000}?)\\{1,20})?({file_name}[^"\\,:]{1,2000}?(\.({file_ext}[^"]{1,2000}))?))""""
    """>({file_name}[^<"']{1,2000})<\/link><\/share>"{0,20}\s{0,100}was created by the application"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```