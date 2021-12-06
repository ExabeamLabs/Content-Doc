#### Parser Content
```Java
{
Name = cef-carbonblack-process-created
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "process-created"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName =CB Defense""", """threatIndicators":""", """processDetails":""", """"eventType":"CREATE_PROCESS""""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"eventTime":({time}\d{1,100})""",
    """"deviceIpAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"deviceName":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({src_host}[^\\\s"]{1,2000})"""",
    """"email":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({user}[^"\\]{1,2000})"""",
    """"eventType":"({alert_name}[^"]{1,2000})"""",
    """"threatIndicators":\[?"({alert_type}[^"]{1,2000})"""",
    """"applicationPath":"({process}(({directory}[^"=,]{1,2000}?)[\\\/]{1,20})?({process_name}[^\/\\"]{1,2000}))"""",
    """"applicationName":"({process_name}[^"]{1,2000})"""",
    """"targetPriorityType":"({alert_severity}[^"]{1,2000})""""
  ]
  DupFields = [ "directory->process_directory" ]


}
```