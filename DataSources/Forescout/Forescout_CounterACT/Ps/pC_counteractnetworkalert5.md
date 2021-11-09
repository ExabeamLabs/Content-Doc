#### Parser Content
```Java
{
Name = counteract-network-alert-5
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Splunk
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """, "alertId":"""",""", "sensorName":"""",""", "engineName":"""",""", "feaAlertCount":"""",""", "feaAlertDetailCount":"""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d[+-]\d\d:\d\d)"""",
    """"sensorName":"({host}[\w\-.]{1,2000})"""",
    """"dstIp":"({dest_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"dstPort":"({dest_port}\d{1,100})"""",
    """"srcHostName":"({src_host}[\w\-.]{1,2000})"""",
    """"srcIp":"({src_ip}[A-Fa-f\d:.]{1,2000})"""",
    """"srcPort":"({src_port}\d{1,100})"""",
    """"name":"({alert_name}[^"]{1,2000})"""",
    """"typeId":"({alert_type}[^"]{1,2000})"""",
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"desc":"({additional_info}[^"]{1,2000})""""
  ]
}
}
```