#### Parser Content
```Java
{
Name = rubrik-account-creation
    DataType = "account-creation"
    Conditions = [ """ Rubrik """, """status="Success"""", """eventName ="Audit.CreateLocalUserAudit"""", """ created local user """ ]
    Fields = ${RubrikCDMParserTemplates.rubrik-events.Fields}[
      """\] ({user}\S{1,2000}?) [^\)]{1,2000}?\) created local user '({account_name}[^']{1,2000}?)'"""
   ]
  
rubrik-events = {
    Vendor = Rubrik
    Product = Rubrik CDM
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
      """nodeId="({host}[^"]{1,2000})"""",
      """nodeIpAddress="({src_ip}[A-Fa-f\d.:]{1,2000}?)"""",
      """eventName ="({event_code}[^"]{1,2000})"""",
      """status="({outcome}[^"]{1,2000})"""",
      """objectName ="(-|({object}[^"]{1,2000}))"""",
      """objectType="({object_type}[^"]{1,2000})"""",
      """objectId="({object_id}[^"]{1,2000})"""",
      """eventSeverity="({alert_severity}[^"]{1,2000})"""",
    ]
    DupFields = [ "host->dest_host"
}
```