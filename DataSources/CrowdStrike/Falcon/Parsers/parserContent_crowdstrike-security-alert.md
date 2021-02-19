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
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"timestamp":"({time}\d+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)""",
      """"FalconHostLink\\*"+:\s*\\*"+({falcon_host_link}[^"]+)"""
    ]
    DupFields = ["event_code->alert_name", "event_code->alert_type", "falcon_host_link->additional_info"]
  }
```