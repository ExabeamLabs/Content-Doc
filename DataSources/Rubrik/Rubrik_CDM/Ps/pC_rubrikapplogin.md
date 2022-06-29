#### Parser Content
```Java
{
Name = rubrik-app-login
    Vendor = Rubrik
    Product = Rubrik CDM
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    DataType = "app-login"
    Conditions = [ """eventType="Audit"""", """ logged in from """, """ Rubrik [""", """clusterName ="""", """ eventName ="""", """ nodeIpAddress="""  ]
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """nodeId="({host}[^"]{1,2000})"""",
      """nodeIpAddress="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""",
      """eventName ="({event_name}[^"]{1,2000})"""",
      """status="({outcome}[^"]{1,2000})"""",
      """objectName ="(-|({object}[^"]{1,2000}))"""",
      """objectType="({object_type}[^"]{1,2000})"""",
      """objectId="({object_id}[^"]{1,2000})"""",
      """eventSeverity="({alert_severity}[^"]{1,2000})"""",
      """\]\s{1,100}({user}[^(]{1,2000})\s(\([^\)]{1,2000}\)\s)*in '[^\']{1,2000}' logged in from""",
      """\(({user_ou}[^)]{1,2000})\) in '[^\']{1,2000}' logged in from""",
      """logged in from\s({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    ]
    DupFields = [ "host->dest_host"]
  

}
```