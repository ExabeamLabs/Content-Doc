#### Parser Content
```Java
{
Name = fireeye-mps-json-generic-alert
    Vendor = FireEye
    Product = FireEye Network Security (NX)
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [""""msg": """",""""product": "Web MPS"""",""""alert": {"""]
    Fields = [
            """"appliance": "({host}[^"]{1,2000})"""",
            """"src":\s\{\s{0,100}(?:"\w+": "[^"]{1,2000}",\s{0,100})*"ip": "({src_ip}[^"]{1,2000})"""",
            """"src":\s\{\s{0,100}(?:"\w+": "[^"]{1,2000}",\s{0,100})*"host": "({src_host}[^"]{1,2000})"""",
    """"explanation":\s\{\s{0,100}(?:"\w+": "[^"]{1,2000}",\s{0,100})*"({alert_type}[^"]{1,2000})": \{\s{0,100}[^\{]{1,2000}\{\s{0,100}(?:"\w+": "[^"]{1,2000}",\s{0,100})*"name": "({alert_name}[^"]{1,2000})"""",
            """"severity": "({alert_severity}[^"]{1,2000})"""", 
        """"occurred": "({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
    """"id": "({alert_id}[^"]{1,2000})","""
    ]
    SOAR {
        IncidentType = "malware"
        DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->malwareName", "alert_id->sourceId", "alert_type->malwareCategory", "alert_severity->sourceSeverity", "src_host->malwareVictimHost"]
        NameTemplate = """FireEye Alert ${alert_name} found"""
        ProjectName = "SOC"
        EntityFields = [
          {EntityType="device", Name="src_address", Fields=["src_ip->ip_address", "src_host->host_name"]}
```