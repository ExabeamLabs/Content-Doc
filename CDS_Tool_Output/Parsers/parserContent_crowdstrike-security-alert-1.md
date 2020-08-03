#### Parser Content
```Java
{
Name = crowdstrike-security-alert-1
    Vendor = CrowdStrike
    Product = Falcon
    Lms = Direct
    DataType = "alert"
    TimeFormat = "epoch"
    Conditions = [ """"event_simpleName":"SuspiciousDnsRequest"""" ]
    Fields = [
      """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
      """"aip":"({host}[^"]+)"""
      """"timestamp":"({time}\d+)""",
      """"DomainName":"({domain}[^"]+)""",
      """"event_simpleName":"({event_code}[^"]+)""",
      """"aid":"({aid}[^"]+)"""
    ]
    DupFields = ["event_code->alert_name", "event_code->alert_type"]
  }
```