#### Parser Content
```Java
{
Name = cef-carbonblack-network-connection
  Vendor = VMware
  Product = Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """threatIndicators":""", """ connection to """ , """sourceAddress":"""", """destinationServiceName =CB Defense"""]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """"eventTime":({time}\d{1,100})""",
    """"deviceIpAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"sourceAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"destAddress":"({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """"destPort":"({dest_port}\d{1,100})""",
    """"sourcePort":"({src_port}\d{1,100})""",
    """"deviceName":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({src_host}[^\\\s"]{1,2000})""",
    """"email":"(({domain}[^\\\s"]{1,2000})\\{1,20})?({user}[^"]{1,2000})""",
    """"eventType":"({alert_name}[^"]{1,2000})"""",
    """"threatIndicators":\[?"({alert_type}[^\s"]{1,2000})""",
    """"applicationPath":"({process}(({directory}[^"=,]{1,2000}?)[\\\/]{1,20})?({process_name}[^\\"\/]{1,2000}))"""",
    """"applicationName":"({process_name}[^"]{1,2000})"""",
    """"targetPriorityType":"({alert_severity}[^"]{1,2000})""""
  ]
  DupFields = [ "directory->process_directory" ]


}
```