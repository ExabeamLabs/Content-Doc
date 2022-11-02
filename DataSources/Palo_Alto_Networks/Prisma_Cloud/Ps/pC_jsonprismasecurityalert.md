#### Parser Content
```Java
{
Name = json-prisma-security-alert
 Vendor = Palo Alto Networks
 Product = Prisma Cloud
 Lms = Direct
 DataType = "alert"
 TimeFormat = "yyyy-MM-dd HH:mm:ss"
 Conditions = [""""alertRuleName":""", """"app":"Prisma Cloud Alert Notification"""", """"source":"Prisma Cloud"""", """"policyName":"""]
 Fields = [ 
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