#### Parser Content
```Java
{
Name = skyformation-prisma-security-alert
 Vendor = Prisma Cloud
 Product = Prisma Cloud
 Lms = Direct
 DataType = "alert"
 IsHVF = true
 TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSZ"""
 Conditions = ["""|Skyformation|""", """destinationServiceName=""", """"source":"Prisma Cloud"""", """"policyName":"""]
 Fields = [
   """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
   """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)\s[\w\-.]+\s{1,100}Skyformation""",
   """"privateIpAddresses":\[.+?"privateIpAddress":"({src_ip}[A-Fa-f:\d.]+)"""",
   """"policyName":"({alert_name}[^"]+)"""",
   """"severity":"({alert_severity}[^"]+)"""",
   """"alertId":"({alert_id}[^"]+)"""",
   """"callbackUrl":"({additional_info}[^"]+)"""",
   """"source":"({app}[^"]+)"""",
   """"url":"({full_url}[^"]+)"""",
   """"policyId":"({policy_id}[^"]+)"""",
   """"accountName":"({user}[^"]+)"""",
   """"alertRuleName":"({alert_type}[^"]+)"""
 ]
}
```