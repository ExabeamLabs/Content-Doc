#### Parser Content
```Java
{
Name = sentinelone-security-alert-10
  Conditions = [ """"threatName":""", """"classification": "Hacktool"""", """"agentComputerName":""" ]

sentinelone-security-alert {
    Vendor = SentinelOne
    Product = Singularity
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?(::ffff:)?({host}\S{1,2000})""",
      """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\dZ)"""",
      """"agentComputerName":\s{0,100}"({src_host}[^"]{1,2000})"""",
      """"agentDomain":\s{0,100}"({src_domain}[^"]{1,2000})"""",
      """"agentLastLoggedInUserName":\s{0,100}"({user}[^"]{1,2000})"""",
      """"processUser":\s{0,100}"(({domain}[^"\\]{1,2000})\\{1,2})?({user}[^"]{1,2000})"""",
      """"externalIp":\s{0,100}"({dest_ip}[\da-fA-F.:]{1,2000})"""",
      """"threatName":\s{0,100}"({alert_name}[^"]{1,2000})"""",
      """"classification":\s{0,100}"({alert_type}[^"]{1,2000})"""",
      """"threatId":\s{0,100}"({alert_id}[^"]{1,2000})"""",
      """"analystVerdict":\s{0,100}"({outcome}[^"]{1,2000})"""",
      """"action":\s{0,100}"({action}[^"]{1,2000})"""",
      """"description":\s{0,100}"({additional_info}[^"]{1,2000})""""
    
}
```