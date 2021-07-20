#### Parser Content
```Java
{
Name = s-mcafee-epo-alert-2
        Vendor = McAfee
        Product = McAfee Endpoint Security
        Lms = Splunk
        DataType = "alert"
        TimeFormat = "yyyy-MM-dd HH:mm:ss"
        Conditions = [ "signature_name=", "dvc_ip_long=", "parameter_value=" ]
        Fields = [
          """dvc_time="({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
          """dvc_ip_long="({host_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """dvc_host="({host}.+?)",""",
          """source_ip="({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """event_id="({alert_id}\d{1,100})""",
          """signature_name="({alert_name}.+?)",""",
          """category="({alert_type}.+?)",""",
          """signature_id="({signature_id}\d{1,100})""",
          """severity="({alert_severity}\d{1,100})""",
          """parameter_name="({additional_info}[^"]{1,2000})""",
          """user="(({domain}[^\\]{1,2000})\\+)?(?: |({user}[^"]{1,2000}))""",
        ]
        SOAR {
            IncidentType = "malware"
            DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_id->sourceId", "alert_name->malwareName", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_ip->malwareVictimHost"]
            NameTemplate = """McAfee EPO Alert ${alert_name} found"""
            ProjectName = "SOC"
            EntityFields = [
              {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```