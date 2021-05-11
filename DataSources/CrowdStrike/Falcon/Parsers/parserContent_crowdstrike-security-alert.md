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
      """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d{1,100})""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"FalconHostLink\\*"{1,20}:\s{0,100}\\*"{1,20}({falcon_host_link}[^"]+)"""
    ]
    DupFields = ["event_code->alert_name", "event_code->alert_type", "falcon_host_link->additional_info"]
  }
```