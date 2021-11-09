#### Parser Content
```Java
{
Name = s-mcafee-dlp-alert-3
  Vendor = McAfee
  Product = McAfee DLP
  Lms = Splunk
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = ["""Occured_(Endpoint)="""" , """ Device_Class_Name="""" , """ Policy_Rule="""" , """Incident_Type=""""]
  Fields = [
    """Occured_\(Endpoint\)="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d)""",
    """Incident_ID="({alert_id}[^"]{1,2000})"""",
    """Severity="({alert_severity}[^"]{1,2000})"""",
    """Policy_Rule="({alert_name}[^"]{1,2000})"""",
    """Computer_Name="({host}[^"]{1,2000})"""",
    """Domain_Account="(({domain}[^\\]{1,2000})\\)?({user}[^"]{1,2000})"""",
    """Incident_Type="({alert_type}[^"]{1,2000})"""",
    """Device_Friendly_Name="({device_id}[^"]{1,2000})"""",
    """Actual_Action="({outcome}[^"]{1,2000})"""",
    """Domain_Account_OU="({additional_info}[^"]{1,2000})"""",
    """Computer_IP="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""""
  ]
}
}
```