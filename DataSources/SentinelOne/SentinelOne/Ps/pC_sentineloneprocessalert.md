#### Parser Content
```Java
{
Name = sentinelone-process-alert
  Vendor = SentinelOne
  Product = SentinelOne
  Lms = Direct
  DataType = "process-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"rulename":""", """"activityType":""", """"ruleid":""" ]
  Fields = [
    """"origagentname":\s{0,100}"({host}[^"]{1,2000})"""",
    """"createdAt":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
    """"srcip":\s{0,100}"({src_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """"dstip":\s{0,100}"({dest_ip}[A-Fa-f\d\.:]{1,2000})"""",
    """"userName":\s{0,100}"({user}[^"]{1,2000})"""",
    """"rulename":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"dveventtype":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"sourceprocesscommandline":\s{0,100}"({command_line}[^,]{1,2000})",""",
    """"primaryDescription":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    """"sourceprocessfilepath":\s{0,100}"({process}({process_directory}[^"]{1,2000})\\\\({process_name}[^"]{1,2000}))"""",
    """"sourceparentprocesspath":\s{0,100}"({parent_process}[^"]{1,2000})"""",
    """"alertid":\s{0,100}({alert_id}[^"]{1,2000}),"""
  ]


}
```