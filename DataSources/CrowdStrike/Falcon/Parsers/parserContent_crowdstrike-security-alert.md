#### Parser Content
```Java
{
Name = crowdstrike-security-alert
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"ActiveDirectPrivilegeEscalation"""" ]
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
      """"timestamp":"({time}\d{1,100})""",
      """"event_simpleName":"({event_code}[^"]{1,2000})""",
      """"aid":"({aid}[^"]{1,2000})""",
      """"FalconHostLink\\*"{1,20}:\s{0,100}\\*"{1,20}({falcon_host_link}[^"]{1,2000})"""
    ]
    DupFields = ["event_code->alert_name", "event_code->alert_type", "falcon_host_link->additional_info"]
  }
```