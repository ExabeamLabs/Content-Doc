#### Parser Content
```Java
{
Name = skyformation-prisma-security-alert
 Vendor = Palo Alto Networks
 Product = Prisma Cloud
 Lms = Direct
 DataType = "alert"
 IsHVF = true
 TimeFormat = """yyyy-MM-dd'T'HH:mm:ss.SSSZ"""
 Conditions = ["""|Skyformation|""", """destinationServiceName =""", """"source":"Prisma Cloud"""", """"policyName":"""]
 Fields = [
   """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
   """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,100}Z)\s[\w\-.]{1,2000}\s{1,100}Skyformation""",
   """"privateIpAddresses":\[.+?"privateIpAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
   """"policyName":"({alert_name}[^"]{1,2000})"""",
   """"severity":"({alert_severity}[^"]{1,2000})"""",
   """"alertId":"({alert_id}[^"]{1,2000})"""",
   """"callbackUrl":"({additional_info}[^"]{1,2000})"""",
   """"source":"({app}[^"]{1,2000})"""",
   """"url":"({full_url}[^"]{1,2000})"""",
   """"policyId":"({policy_id}[^"]{1,2000})"""",
   """"accountName":"({user}[^"]{1,2000})"""",
   """"alertRuleName":"({alert_type}[^"]{1,2000})"""
 ]


}
```