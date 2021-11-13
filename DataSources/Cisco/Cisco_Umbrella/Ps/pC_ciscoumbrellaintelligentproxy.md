#### Parser Content
```Java
{
Name = cisco-umbrella-intelligent-proxy
 Product = Cisco Umbrella
 Vendor = Cisco
 Lms = Direct
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
 DataType = "web-activity"
 Conditions = [ """"Type":"UmbrellaIntelligentProxyLogs""", """Verdict_s""", """TenantId""", """statusCode_s""" ]
 Fields = [
   """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
   """TimeGenerated"{1,20}:"{1,20}({time}[^"]{1,2000})""",
   """"Computer"{1,20}:"{1,20}({host}[^"]{1,2000})?"{1,20

}
```