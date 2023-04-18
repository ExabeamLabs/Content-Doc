#### Parser Content
```Java
{
Name = exabeam-cr-kv-alert-trigger-success-correlationrule
Vendor = Exabeam
Product = Correlation Rule
Lms = Exabeam
DataType = "exabeam-security-alert"
TimeFormat = "epoch"
Conditions = [ """operation="alert-trigger"""" , """alert_source="correlation"""" ]
Fields = [
"""usecases="({rule_usecases}[^"]+)"""",
"""mitre_labels="({mitre_labels}[^"]+)"""",
"""alert_severity="({alert_severity}[^"]+)"""",
"""rule_severity="({rule_severity}[^"]+)"""",
"""alert_source="({alert_source}correlation)"""",
"""alert_name="({alert_name}[^"]+)"""",
"""alert_type="({alert_type}[^"]+)"""",
"""dest_host="({dest_host}[^"]+)"""",
"""dest_ip="({dest_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({dest_port}\d+))?"""",
"""operation="({activity}[^"]+)"""",
"""rule_description="({rule_description}[^"]+)"""",
"""rule_id="({rule_id}[^"]+)"""",
"""rule="({rule}[^"]+)"""",
"""rule_reason="({rule_reason}[^"]+)"""",
"""rule_type="({rule_type}[^"]+)"""",
"""src_host="({src_host}[^"]+)"""",
"""src_ip="({src_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({src_port}\d+))?"""",
"""trigger_time="({time}\d{10})"""",
"""url="({url}[^"]+)"""",
"""user="({user}[^"]+)""""
]
  SOAR {
    IncidentType = "ueba"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo",  "user->uebaUserId", "rule_description->description", "alert_severity->sourceSeverity", "alert_id->sourceId"]
    NameTemplate = """Exabeam Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name ="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]

}
```