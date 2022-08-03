#### Parser Content
```Java
{
Name = crowdstrike-security-alert-7
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"eventType":"IdpDetectionSummaryEvent"""", """"Severity":""", """"FalconHostLink":"""", """"DetectName":"""", """destinationServiceName =CrowdStrike""" ]
  Fields = [
    """"eventCreationTime":({time}\d{1,20}),""",
    """"DetectId":"({alert_id}[^"]{1,2000})"""",
    """"Severity":({alert_severity}\d{1,5}),""",
    """"DetectName":"({alert_name}[^"]{1,2000})"""",
    """"Technique":"({alert_type}[^"]{1,2000})"""",
    """"eventType":"({alert_type}[^"]{1,2000})"""",
    """"SourceAccountDomain":"({domain}[^"]{1,2000})"""",
    """"SourceAccountName":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"SourceAccountUpn":"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """"SourceAccountObjectSid":"({user_sid}[^"]{1,2000})"""",
    """"SourceEndpointHostName":"({src_host}[^"]{1,2000})"""",
    """"SourceEndpointIpAddress":"({src_ip}[a-fA-F\d:\.]{1,2000})"""",
    """"TargetEndpointHostName":"({dest_host}[^"]{1,2000})"""",
    """"DetectDescription":"({additional_info}[^"]{1,2000})"""",
    """"FalconHostLink":"({falcon_host_link}[^"]{1,2000})"""",
    """"Tactic":"({category}[^"]{1,2000})"""",
  ]


}
```